use std::future::Future;
use std::time::Duration;

use bas_core::Uuid;
use bas_core::credential::MachineToken;
use bas_core::secrets::{Identifier, Project, Secret, Session};
use color_eyre::eyre::OptionExt;
use crossterm::event::Event as CrosstermEvent;
use futures::{FutureExt, StreamExt};
use tokio::sync::{mpsc, oneshot};

use crate::app::Listed;
use crate::ui::Status;

/// How often tick events fire. Ticks drive the clipboard countdown.
const TICK_FPS: f64 = 4.0;

/// Everything the main loop reacts to.
#[derive(Debug)]
pub enum Event {
    /// Emitted on a fixed schedule.
    Tick,
    /// A terminal event.
    Crossterm(CrosstermEvent),
    /// A result reported back by a spawned network task, or a request from the app itself.
    App(AppEvent),
}

/// Results of network tasks, each sent once the server has answered.
///
/// Failures carry the app's one error type, with fixed wording from `bas-core`.
#[derive(Debug)]
pub enum AppEvent {
    /// Login finished. Boxed because a signed-in session is much larger than the other events.
    Connected(Box<color_eyre::Result<Session>>),
    /// The sign-in screen's token signed in, and its profile still has to be saved.
    SignedIn(Box<(Session, MachineToken)>),
    /// A project listing arrived. When it follows a write, `select` names the project to
    /// highlight and `done` is the status line text.
    Projects {
        listed: Listed<Project>,
        select: Option<Uuid>,
        done: Option<String>,
    },
    /// A secret listing arrived for the given project, or for all projects. When it follows
    /// a write, `done` is the status line.
    Secrets {
        project: Option<Uuid>,
        listed: Listed<Identifier>,
        done: Option<Status>,
    },
    /// One secret was read.
    Secret {
        request: u64,
        result: color_eyre::Result<Secret>,
    },
    /// A create or update from form save `form` finished and the secret was read back.
    SecretSaved {
        form: u64,
        result: color_eyre::Result<Secret>,
    },
    /// A write was refused or failed. `action` completes "Could not ...".
    WriteFailed {
        action: String,
        error: color_eyre::Report,
        outcome: WriteOutcome,
        /// The save request of the secret form that started the write, if one did.
        form: Option<u64>,
    },
    /// A broker call finished, in broker mode.
    #[cfg(unix)]
    Broker(Box<crate::broker::Update>),
    /// Leave the application.
    Quit,
}

/// What a failed write means for the server's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The SDK or server refused it, so nothing changed and the form can be retried.
    Refused,
    /// No usable answer arrived, so the server may have applied it.
    Unknown,
}

/// Terminal event handler.
#[derive(Debug)]
pub struct EventHandler {
    sender: mpsc::UnboundedSender<Event>,
    receiver: mpsc::UnboundedReceiver<Event>,
    #[cfg_attr(
        not(unix),
        expect(dead_code, reason = "only broker mode, on unix, opens an editor")
    )]
    control: mpsc::UnboundedSender<Control>,
}

/// Requests to the task that reads the terminal.
#[derive(Debug)]
#[cfg_attr(
    not(unix),
    expect(dead_code, reason = "only broker mode, on unix, opens an editor")
)]
enum Control {
    /// Stop reading the terminal, and answer once reading has stopped.
    Pause(oneshot::Sender<()>),
    /// Read the terminal again.
    Resume,
}

impl EventHandler {
    /// Creates the handler and spawns the task that reads terminal events and emits ticks.
    ///
    /// # Errors
    ///
    /// Fails when the exit signal handlers cannot be installed.
    pub fn new() -> color_eyre::Result<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let (control, control_receiver) = mpsc::unbounded_channel();
        let actor = EventTask {
            sender: sender.clone(),
            control: control_receiver,
            exit: ExitSignals::new()?,
        };
        tokio::spawn(actor.run());
        Ok(Self {
            sender,
            receiver,
            control,
        })
    }

    /// Stops reading the terminal until [`Self::resume`], so a program started in the
    /// foreground, such as an editor, gets every key.
    #[cfg(unix)]
    pub async fn pause(&self) {
        let (done, stopped) = oneshot::channel();
        if self.control.send(Control::Pause(done)).is_ok() {
            let _ = stopped.await;
        }
    }

    /// Reads the terminal again after [`Self::pause`].
    #[cfg(unix)]
    pub fn resume(&self) {
        let _ = self.control.send(Control::Resume);
    }

    /// Waits for the next event.
    ///
    /// # Errors
    ///
    /// Fails when every sender is gone, which happens only if the event task died.
    pub async fn next(&mut self) -> color_eyre::Result<Event> {
        self.receiver
            .recv()
            .await
            .ok_or_eyre("Failed to receive event")
    }

    /// Queues an app event for the next loop iteration.
    pub fn send(&mut self, app_event: AppEvent) {
        // The receiver lives as long as this struct, so the send cannot fail.
        let _ = self.sender.send(Event::App(app_event));
    }

    /// Runs a network task off the UI loop and delivers its result as an app event.
    pub fn spawn(&self, task: impl Future<Output = AppEvent> + Send + 'static) {
        let sender = self.sender.clone();
        tokio::spawn(async move {
            // The app may have quit while the task ran; the result is then unwanted.
            let _ = sender.send(Event::App(task.await));
        });
    }
}

/// Reads crossterm events and emits ticks.
struct EventTask {
    sender: mpsc::UnboundedSender<Event>,
    control: mpsc::UnboundedReceiver<Control>,
    exit: ExitSignals,
}

impl EventTask {
    async fn run(mut self) {
        let tick_rate = Duration::from_secs_f64(1.0 / TICK_FPS);
        let mut reader = crossterm::event::EventStream::new();
        let mut tick = tokio::time::interval(tick_rate);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let step = {
                let tick_delay = tick.tick();
                let crossterm_event = reader.next().fuse();
                tokio::select! {
                  _ = self.sender.closed() => Step::Stop,
                  control = self.control.recv() => Step::Control(control),
                  () = self.exit.recv() => Step::Quit,
                  _ = tick_delay => Step::Tick,
                  event = crossterm_event => Step::Terminal(event),
                }
            };
            match step {
                // Without a control sender the handler is gone.
                Step::Stop | Step::Control(None) => break,
                Step::Quit => self.send(Event::App(AppEvent::Quit)),
                Step::Tick => self.send(Event::Tick),
                Step::Terminal(Some(Ok(event))) => self.send(Event::Crossterm(event)),
                // The terminal is gone or unreadable, so quit the way `q` does.
                Step::Terminal(Some(Err(_)) | None) => {
                    self.send(Event::App(AppEvent::Quit));
                    break;
                }
                Step::Control(Some(Control::Pause(done))) => {
                    drop(reader);
                    let _ = done.send(());
                    // Ticks and signals wait too; the foreground program owns the terminal.
                    loop {
                        match self.control.recv().await {
                            Some(Control::Resume) => break,
                            Some(Control::Pause(done)) => {
                                let _ = done.send(());
                            }
                            None => return,
                        }
                    }
                    reader = crossterm::event::EventStream::new();
                }
                Step::Control(Some(Control::Resume)) => {}
            }
        }
    }

    fn send(&self, event: Event) {
        // Shutting down drops the receiver, so a failed send is expected then.
        let _ = self.sender.send(event);
    }
}

/// What woke the event task.
enum Step {
    Stop,
    Quit,
    Tick,
    Terminal(Option<std::io::Result<CrosstermEvent>>),
    Control(Option<Control>),
}

/// Signals that end the app the same way as `q`, so a copied value is still cleared when the
/// terminal closes or the process is asked to stop.
struct ExitSignals {
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    close: tokio::signal::windows::CtrlClose,
}

impl ExitSignals {
    #[cfg(unix)]
    fn new() -> color_eyre::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            hangup: signal(SignalKind::hangup())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    #[cfg(windows)]
    fn new() -> color_eyre::Result<Self> {
        Ok(Self {
            close: tokio::signal::windows::ctrl_close()?,
        })
    }

    #[cfg(unix)]
    async fn recv(&mut self) {
        tokio::select! {
            _ = self.hangup.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }

    #[cfg(windows)]
    async fn recv(&mut self) {
        self.close.recv().await;
    }
}

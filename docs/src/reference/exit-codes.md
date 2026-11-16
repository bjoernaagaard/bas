# Exit codes

Look up the exit code in the table to learn whether `bas` wrote anything and what to do next. Every `bas` command uses the same codes, and `bas run` and `bas env run` exit with the program's own status once the program starts.

| Code | Meaning | What to do next |
|---|---|---|
| 0 | The command succeeded, or the write was read back and verified | Nothing |
| 1 | The command failed before a write, or Secrets Manager refused the write. For `bas doctor`, a check failed | Read the message. Nothing was written. |
| 2 | The usage or the input syntax was invalid. For `bas doctor`, a check warned and none failed | Run `bas <command> --help`. For `bas doctor`, read the warning and its `fix:` line |
| 3 | Secrets Manager acknowledged the write, but `bas` couldn't verify it | Check the secret in the web vault before another write |
| 4 | The outcome of the write is unknown | Check the secret in the web vault before another write |
| 126 | `bas run` found the program but couldn't start it | Check the program's permissions |
| 127 | `bas run` couldn't find the program | Check the program name and `PATH` |
| any other | The exit status of the program that `bas run` started | See the program's documentation |

Don't retry a write automatically after code 3 or 4, because a second write could overwrite a change that the first one made.

```text
on(exit code from bas create or bas update)
  0      the receipt says verified, and you are done
  3, 4   don't retry, and look at the secret in the web vault first
  1, 2   nothing was written, so fix the cause and run again

on(exit code from bas doctor)
  0      no check failed or warned
  1      a check failed
  2      a check warned and none failed
```

A warning from `bas doctor` means `bas` couldn't gather the evidence for a verdict, for example because the broker didn't answer.

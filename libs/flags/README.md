# Build-time settings

`BH_FLAG_REMOVAL_WAIT=5m` opts this binary into a five-minute removal wait (default: three days). Only this exact value is accepted. All non-default settings are shown in About BaseHero. A non-default build cannot authenticate a default checker: both ends bind the setting digest into the channel's app-root comparison, once each; default builds retain the old root.

`BH_RELEASE=1` refuses a build with any off-default setting. `BH_BUILD_NUMBER` and `BH_SOURCE_COMMIT` are optional build metadata displayed by the client (unset: `unknown`). These are build inputs, not runtime environment settings. Never use a flagged build for released clients or checkers.

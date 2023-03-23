export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

fixes the following error on some Mac OS X

objc[22402]: +[__NSPlaceholderDate initialize] may have been in progress in another thread when fork() was called.

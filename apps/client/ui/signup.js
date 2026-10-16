// First-run presentation only. Native account commands own identity, storage,
// key release, kit destinations and the note binding. No account id, path,
// key handle or recovery private material is supplied by this page.
export function mountSignup(root, invoke, openBoundNote) {
  const location = document.querySelector('header strong');
  const footer = document.querySelector('footer');
  let screen;
  let printKit;
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text != null) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const button = (text, action, primary = false) => {
    const node = element('button', text, primary ? 'primary' : 'secondary');
    node.type = 'button';
    node.addEventListener('click', async () => {
      node.disabled = true;
      try { await action(); }
      catch { showError('That didn’t work. Your account and recovery kit are still here; try again.'); }
      finally { node.disabled = false; }
    });
    return node;
  };
  const controls = (...nodes) => {
    const row = element('div', null, 'signup-actions');
    row.append(...nodes);
    root.append(row);
  };
  const heading = (step, title, explanation) => {
    root.replaceChildren();
    root.className = 'signup';
    root.append(element('p', step, 'label'), element('h1', title), element('p', explanation, 'signup-intro'));
    location.textContent = step === 'WELCOME' ? 'START' : step;
    footer.textContent = 'Cloud sync not connected';
  };
  const showError = (text) => {
    let error = root.querySelector('[role="alert"]');
    if (!error) {
      error = element('p', null, 'signup-error');
      error.setAttribute('role', 'alert');
      root.append(error);
    }
    error.textContent = text;
  };
  const draw = (next) => {
    screen = next;
    if (next.screen === 'kit') {
      printKit = element('pre', `BaseHero recovery kit\n\nRecovery code: ${next.code}\n\nKeep this code and your password. You need both if you lose access to your devices. BaseHero cannot reset a forgotten password. Keep the kit somewhere you can reach if this Mac is lost. The password is not in this file.\n`, 'signup-print-kit');
    } else if (next.screen !== 'confirm') {
      printKit = undefined;
    }
    switch (next.screen) {
      case 'welcome':
        heading('WELCOME', 'A place for your thoughts.', 'Keep notes in your own space. You do not need an email to create an account.');
        controls(
          button('Create my account', async () => draw(await invoke('account_suggest_password')), true),
          button('I already have an account', async () => draw(await invoke('account_return'))),
        );
        break;
      case 'password': {
        heading('ACCOUNT / PASSWORD', 'Choose your password', 'You’ll need this and your recovery kit if you lose access to your devices. Keep your password somewhere you can reach without BaseHero.');
        root.append(element('p', 'Suggested five-word passphrase', 'signup-caption'));
        root.append(element('p', next.suggested, 'signup-phrase'));
        const own = element('section', null, 'signup-own');
        const label = element('label', 'Your password');
        const input = document.createElement('input');
        input.type = 'password';
        input.autocomplete = 'new-password';
        input.id = 'signup-own-password';
        label.htmlFor = input.id;
        own.append(label, input);
        own.hidden = true;
        root.append(own);
        if (next.error) showError(next.error);
        controls(
          button('Use my own password', async () => { own.hidden = false; input.focus(); }),
          button('Use suggested password', async () => { own.hidden = true; input.value = ''; }),
          button('Use this password', async () => draw(await invoke('account_create', { password: next.suggested })), true),
          button('Continue with this password', async () => {
            if (!input.value) { showError('Choose a password first.'); return; }
            draw(await invoke('account_create', { password: input.value }));
            input.value = '';
          }),
        );
        break;
      }
      case 'kit': {
        heading('ACCOUNT / RECOVERY KIT', 'Keep your way back in', 'Keep your password and this recovery kit. BaseHero cannot reset a forgotten password. Losing every device and the code loses your account.');
        root.append(element('p', next.code, 'signup-kit-code'));
        const routes = element('div', null, 'kit-routes');
        const passwords = button('Save to Passwords — unavailable in this build', async () => {});
        passwords.disabled = true;
        routes.append(passwords,
          button('Print', async () => route(await invoke('account_print_kit'))),
          button('Email to myself', async () => route(await invoke('account_email_kit'))),
          button('Save a file', async () => route(await invoke('account_save_kit_file'))),
        );
        root.append(routes, element('p', 'Saving it only on this device won’t help if you lose the device.', 'signup-caption'), element('p', 'Apple Passwords saving is not available in this unsigned build. Use Print, your own mail app, or the system file picker instead.', 'signup-caption'));
        break;
      }
      case 'confirm':
        heading('ACCOUNT / RECOVERY KIT', 'Did you keep your kit?', 'Opening a print or mail destination does not save your kit. If you cancelled or it did not work, choose another way.');
        if (next.route === 'email') root.append(element('p', 'Anyone who can read that email can read your kit. You must address and send it in your own mail app.', 'signup-caption'));
        controls(
          button('Try another way', async () => draw(await invoke('account_screen')), true),
          button('I saved my kit', async () => draw(await invoke('account_confirm_kit'))),
        );
        break;
      case 'ready':
        heading('ACCOUNT / READY', 'Opening your note', 'Your account is ready on this Mac.');
        void (async () => {
          try { await invoke('account_open_note'); await openBoundNote(); }
          catch { showError('Your account is here. Notes will open after your own base is ready.'); }
        })();
        break;
      case 'update':
        heading('ACCOUNT / UPDATE REQUIRED', 'Update BaseHero to open this account', 'This account was saved by a newer version. Your data has not been changed.');
        break;
      case 'return':
        heading('ACCOUNT / RETURN', 'I already have an account', 'Use another signed-in device or your recovery kit to add this device. Email is not an account login.');
        controls(button('Back', async () => draw({screen:'welcome'})));
        break;
      case 'retry':
        heading('ACCOUNT / RETRY', 'Try again', 'BaseHero couldn’t open this account. Your account is still on this Mac. Try again when you’re ready.');
        controls(button('Try again', async () => draw(await invoke('account_retry')), true));
        break;
      default:
        heading('ACCOUNT / UNAVAILABLE', 'Account unavailable', 'Your local account has not been changed. Try again when the native account service is available.');
        controls(button('Try again', async () => draw(await invoke('account_screen')), true));
    }
    if (printKit) root.append(printKit);
  };
  const route = async (result) => {
    if (result?.result === 'saved') { draw(await invoke('account_screen')); return; }
    if (result?.result === 'opened') { draw({screen:'confirm', route:result.route}); return; }
    // Cancelled or failed: never claim success; the code remains available.
    draw(await invoke('account_screen'));
    if (result?.result === 'failed') showError('That save didn’t work. Try another destination.');
  };
  return invoke('account_screen').then(draw);
}

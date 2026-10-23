// Recovery code text stays in this form only until the local checksum check;
// the host owns recovery, password attempts, admission and download progress.
const el=(tag,text,cls)=>{const node=document.createElement(tag);if(text!=null)node.textContent=text;if(cls)node.className=cls;return node;};
const button=(label,action)=>{const node=el('button',label);node.type='button';node.addEventListener('click',()=>void action(node));return node;};
const date=ms=>new Intl.DateTimeFormat(undefined,{dateStyle:'long',timeStyle:'short'}).format(new Date(ms));
const thisDevice=()=>/Mac/.test(navigator.platform)?'Mac':'device';
export function recoveryScreen(root, invoke, {heading,ready,back,refused}) {
  let attempt=0;
  const actions=(...buttons)=>{const row=el('div',null,'signup-actions');row.append(...buttons);root.append(row);};
  const choice=()=>{
    heading('WELCOME','Welcome back','Do you still have BaseHero on another device?','');
    actions(button('Use my other device',back),button('Use password and recovery kit',form));
  };
  const showRefusal=result=>{
    if(result.reason==='not_recognised'){
      heading('ACCOUNT / RECOVERY','Code not recognised','Check the code against your saved kit. If you changed your password, use the newest kit.','');
      root.append(el('p','This did not use a password attempt.'));
    } else if(result.reason==='wait'){
      heading('ACCOUNT / RECOVERY','Wait before trying again',`You can try again at ${date(result.next_try_ms)}.`,'');
    } else if(result.reason==='unreachable'){
      heading('ACCOUNT / RECOVERY','Can’t reach recovery right now','','');
    } else {
      heading('ACCOUNT / RECOVERY','That password isn’t right.',result.next_try_ms?`You can try again at ${date(result.next_try_ms)}.`:`${result.tries_left} tries left`,'');
    }
    actions(button(result.reason==='wait'?'Back to recovery':'Try again',form),button('Use my other device',back));
    refused?.(result);
  };
  const form=()=>{
    heading('ACCOUNT / RECOVERY','Open your recovery kit','','');
    const code=el('input'),password=el('input');code.autocomplete='off';code.spellcheck=false;password.type='password';password.autocomplete='current-password';
    const field=(text,input)=>{const label=el('label',text);label.append(input);return label;};
    root.append(field('Recovery code',code),field('Password',password));
    actions(button('Recover account',async node=>{
      node.disabled=true;
      let typed=code.value.trim();
      code.value=''; // No longer retained in the page after submitting.
      let valid;
      try{valid=await invoke('account_check_code',{code:typed});}
      catch{typed='';showRefusal({reason:'unreachable'});return;}
      if(!valid){typed='';showRefusal({reason:'not_recognised'});return;}
      heading('ACCOUNT / RECOVERY','Opening your account','Keep BaseHero open until your notes have downloaded.','');
      const progress=el('p','Checking your account…','join-progress');root.append(progress);
      const current=++attempt;
      let admitted=false;
      const poll=async()=>{while(current===attempt){
        try {const status=await invoke('account_recovery_status');
          if((status?.state==='admitted'||status?.state==='bootstrapping')&&!admitted){
            admitted=true;
            heading('ACCOUNT / RECOVERY','Your account is open',`This ${thisDevice()} has been added. Downloading your notes and images now.`,'');
            root.append(el('p','Your other devices have been told.'),progress);
          }
          if(status?.state==='bootstrapping'){progress.textContent=`Downloading your notes: ${status.done??0} of ${status.total??0}`;}
          if(status?.state==='ready')return;
        }catch{return;}
        await new Promise(resolve=>setTimeout(resolve,500));
      }};
      const watching=poll();
      try {const recovering=invoke('account_recover',{password:password.value,code:typed});
        typed='';
        const result=await recovering;
        attempt++;
        if(result.screen==='recover_refused'){showRefusal(result);return;}
        if(result.screen==='recovered' || result.screen==='ready'){
          heading('ACCOUNT / RECOVERY','Your account is open',`This ${thisDevice()} has been added. Downloading your notes and images now.`,'');
          root.append(el('p','Your other devices have been told.'));
          const stage=el('p','Downloading your notes…','join-progress');root.append(stage);
          const status=await invoke('account_recovery_status').catch(()=>null);
          if(status?.state==='bootstrapping')stage.textContent=`Downloading your notes: ${status.done} of ${status.total}`;
          await ready();return;
        }
      } catch {attempt++;showRefusal({reason:'unreachable'});} finally {void watching;password.value='';}
    }),button('Use my other device',back));
  };
  return {choice,form,showRefusal};
}

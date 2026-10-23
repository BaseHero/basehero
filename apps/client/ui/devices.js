// Device controls are presentations of verified host eligibility. The page
// never estimates maturity or an effective deadline from its own clock.
import { renderAlerts } from './alerts.js';
import { printableKit } from './kit-print.js';

const el = (tag,text,cls) => {const node=document.createElement(tag);if(text!=null)node.textContent=text;if(cls)node.className=cls;return node;};
const button = (text,click,primary=false) => {const node=el('button',text,primary?'primary':'secondary');node.type='button';node.addEventListener('click',()=>void click(node));return node;};
const row = (...nodes) => {const div=el('div',null,'device-actions');div.append(...nodes);return div;};
export function formatWait(ms) {
  if (!Number.isSafeInteger(ms) || ms <= 0) return 'a moment';
  const [unit,size] = ms % 86400000 === 0 ? ['day',86400000] : ms % 3600000 === 0 ? ['hour',3600000] : ['minute',60000];
  const n=Math.ceil(ms/size);
  return `${n===3 && unit==='day'?'three':n} ${unit}${n===1?'':'s'}`;
}
export function formatDeadline(ms) {
  const parts = new Intl.DateTimeFormat('en-GB',{weekday:'long',day:'numeric',month:'long',hour:'numeric',minute:'2-digit',hour12:true}).formatToParts(new Date(ms));
  const value=type=>parts.find(part=>part.type===type)?.value??'';
  return `${value('weekday')}, ${value('day')} ${value('month')} at ${value('hour')}:${value('minute')} ${value('dayPeriod').toLowerCase()}`;
}
const operationError = error => ({
  'kit not changed':'Your recovery kit wasn’t changed. Your old kit still works.',
  busy:'Another change is in progress. Try again in a moment.',
  'invalid password':'That password isn’t right.',
  'wrong password':'That password isn’t right.',
  'needs kit':'Enter the recovery code from your current kit.',
  'not signed':'Not confirmed. Nothing was changed.',
  'not accepted':'The change was not accepted. Try again.',
}[String(error)] ?? 'Can’t reach recovery right now');

export function devicesButton(invoke) {
  return button('Devices',()=>openDevices(invoke));
}
export async function openDevices(invoke) {
  const dialog=el('dialog',null,'devices-dialog');
  const content=el('div',null,'devices-content');dialog.append(content);document.body.append(dialog);
  const close=()=>{dialog.close();dialog.remove();};
  dialog.addEventListener('cancel',event=>{event.preventDefault();close();});
  dialog.showModal();
  const error=message=>{const p=el('p',message,'signup-error');p.setAttribute('role','alert');content.append(p);};
  const controls=(...actions)=>content.append(row(...actions));
  const back=()=>void refresh();
  const refresh=async()=>{
    try {
      const pending=await invoke('devices_kit_screen');
      if(pending?.screen==='new_kit'){newKit(pending);return;}
      draw(await invoke('devices_view'));
    }catch {content.replaceChildren(el('h2','Your devices'));error('Can’t reach recovery right now');controls(button('Close',close));}
  };
  const perform=async(command,args)=>{
    content.replaceChildren(el('h2','Submitting removal…'));
    try {const result=await invoke(command,args);if(result?.screen==='recover_refused'){refusal(result,back);return;}
      if(result?.screen==='cancel_took_effect'){content.replaceChildren(el('p','This removal already took effect.'));controls(button('Back',back));return;}
      if(result?.screen==='erased' || result?.screen==='erase_incomplete'){erased(result);return;}
      await refresh();
    }catch(e){await refresh();error(operationError(e));}
  };
  const refusal=(result,retry)=>{
    const title=result.reason==='not_recognised'?'Code not recognised':result.reason==='wait'?'Wait before trying again':result.reason==='password'?'That password isn’t right.':'Can’t reach recovery right now';
    content.replaceChildren(el('h2',title));
    if(result.reason==='not_recognised')content.append(el('p','Check the code against your saved kit. If you changed your password, use the newest kit.'),el('p','This did not use a password attempt.'));
    if(result.reason==='password')content.append(el('p',result.next_try_ms?`You can try again at ${new Intl.DateTimeFormat(undefined,{dateStyle:'long',timeStyle:'short'}).format(new Date(result.next_try_ms))}.`:`${result.tries_left} tries left`));
    if(result.reason==='wait')content.append(el('p',`You can try again at ${new Intl.DateTimeFormat(undefined,{dateStyle:'long',timeStyle:'short'}).format(new Date(result.next_try_ms))}.`));
    controls(button(result.reason==='wait'?'Back to devices':'Try again',retry),button('Close',close));
  };
  const kit=(command,args)=>{
    content.replaceChildren(el('h2','Remove now with password and kit'));
    const password=el('input'),code=el('input');password.type='password';password.autocomplete='current-password';code.autocomplete='off';
    const field=(label,input)=>{const block=el('label',label);block.append(input);return block;};
    content.append(field('Password',password),field('Recovery code',code));
    controls(button('Remove now with password and kit',()=>perform(command,{...args,password:password.value,code:code.value}),true),button('Back',back));
  };
  const erased=result=>{
    content.replaceChildren(el('h2',result.screen==='erased'?'This device was removed':'Erasure incomplete'),
      el('p',result.screen==='erased'?'This device was removed from your account. BaseHero erased this account’s data here.':'BaseHero couldn’t finish erasing this account’s data.'));
    if(result.screen==='erased')content.append(el('p',`${result.unsent} unsynced changes were not sent.`));
    controls(button(result.screen==='erased'?'Add an account':'Try again',()=>{close();location.reload();},true));
  };
  const changePassword=view=>{
    content.replaceChildren(el('h2','Change password & recovery kit'));
    const current=el('input'),next=el('input'),keep=el('input'),code=el('input');
    current.type=next.type='password';current.autocomplete='current-password';next.autocomplete='new-password';keep.type='checkbox';code.autocomplete='off';
    const field=(text,input)=>{const label=el('label',text);label.append(input);return label;};
    content.append(field('Current password',current),field('New password',next),field('Keep my current password (new recovery kit only)',keep));
    if(view.password_change_needs_kit)content.append(field('Recovery code',code));
    content.append(el('p','Either way you get a new recovery kit and the old one stops working at once.'));
    controls(button('Continue',async()=>{try{const result=await invoke('account_change_password',{current:current.value,newPassword:keep.checked?null:next.value,code:view.password_change_needs_kit?code.value:null});if(result?.screen==='new_kit')newKit(result);else if(result?.screen==='recover_refused')refusal(result,()=>changePassword(view));else await refresh();}catch(e){error(operationError(e));}},true),button('Back',back));
  };
  const newKit=result=>{
    content.replaceChildren(el('h2','Keep your way back in'),el('p',result.code,'signup-kit-code'),
      el('p','Saving it only on this device won’t help if you lose the device.'),printableKit(result.code));
    const confirm=async()=>{try {await invoke('account_confirm_new_kit');await refresh();}catch(e){error(operationError(e));}};
    const route=async command=>{
      try {const saved=await invoke(command);
        if(saved.result==='saved') {await refresh();return;}
        if(saved.result==='opened') {
          content.replaceChildren(el('h2','Did you keep your kit?'),
            el('p','Opening a print or mail destination does not save your kit. If you cancelled or it did not work, choose another way.'));
          controls(button('Try another way',()=>newKit(result)),button('I saved my kit',confirm));
          return;
        }
        if(saved.result==='failed')error('That save didn’t work. Try another destination.');
      }catch(e){error(operationError(e));}
    };
    controls(button('Print',()=>route('account_print_kit')),button('Email to myself',()=>route('account_email_kit')),
      button('Save a file',()=>route('account_save_kit_file')),button('I saved my kit',confirm,true),button('Close',close));
  };
  const draw=view=>{
    content.replaceChildren(el('h2','Your devices'));
    for(const device of view.devices??[]){
      const line=el('section',null,'device-row');line.append(el('strong',`${device.name??'Device'}${device.this_device?' · this device':''}`));
      if(device.added_ms!=null)line.append(el('small',`Added ${new Intl.DateTimeFormat(undefined,{dateStyle:'medium'}).format(new Date(device.added_ms))}`));
      if(device.this_device && device.pending){line.append(el('p',`This device will be removed from your account on ${formatDeadline(device.pending.deadline_ms)}. Requested from ${device.pending.requested_by??'another device'}.`,'device-warning'),el('p','When the removal takes effect, BaseHero will erase this account’s data from this device.'));}
      if(device.submitting){line.append(el('p','Submitting removal…'));}
      else if(device.pending && !device.this_device){
        line.append(el('h3','Removal pending'),el('p',`Removal takes effect ${formatDeadline(device.pending.deadline_ms)}`,'device-warning'),
          el('p',`${device.name??'This device'} still has access until then.`));
        const actions=[];
        if(device.can_cancel)actions.push(button('Cancel removal',()=>perform('devices_cancel_removal',{request:device.pending.request})));
        if(device.can_remove_now)actions.push(button('Remove now with password and kit',()=>kit('devices_remove_now',{device:device.id_hex})));
        line.append(row(...actions));
      } else if(device.can_remove){
        line.append(row(button(device.this_device?'Remove this device':'Remove',()=>{
          content.replaceChildren(el('h2',device.this_device?'Remove this device?':`Remove ${device.name??'this device'}?`),
            el('p',device.this_device?'Your unsynced changes will be sent before this device is removed.':`Removal takes effect ${formatWait(view.wait_ms)} after it is saved.`));
          controls(button(device.this_device?'Remove this device':`Remove after ${formatWait(view.wait_ms)}`,
            ()=>perform(device.this_device?'devices_remove_self':'devices_request_removal',device.this_device?{withoutSync:false}:{device:device.id_hex}),true),
            ...(device.can_remove_now?[button('Remove now with your recovery kit',()=>kit('devices_remove_now',{device:device.id_hex}))]:[]),button('Back',back));
        })));
      }
      content.append(line);
    }
    controls(button('Change password & recovery kit',()=>changePassword(view)),button('Security alerts',async()=>{
      try{renderAlerts(content,await invoke('alerts_list'));controls(button('Back',back));}catch(e){error(operationError(e));}
    }),...(/Android/i.test(navigator.userAgent)?[button('About BaseHero',()=>window.__bhAbout?.())]:[]),button('Close',close));
  };
  await refresh();
}

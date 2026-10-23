// Both kit-save routes print the same code and instructions. This text is
// created only while native reports a kit to save; it is never page content.
export function printableKit(code) {
  const print = document.createElement('pre');
  print.className = 'signup-print-kit';
  print.textContent = `BaseHero recovery kit\n\nRecovery code: ${code}\n\nKeep this code and your password. You need both if you lose access to your devices. BaseHero cannot reset a forgotten password. Keep the kit somewhere you can reach if this Mac is lost. The password is not in this file.\n`;
  return print;
}

import SettingsMain from "./SettingsMain";
import MailboxPage from "./MailboxPage";
import OnionPage from "./OnionPage";

export default function SettingsPage(props) {
  if (props.sub === "mailbox") {
    return <MailboxPage notify={props.notify} onClose={props.onClose} />;
  }
  if (props.sub === "onion") {
    return <OnionPage notify={props.notify} onClose={props.onClose} />;
  }
  return (
    <SettingsMain
      notify={props.notify}
      onClose={props.onClose}
      onLocked={props.onLocked}
      onOpenMailbox={props.onOpenMailbox}
      onOpenOnion={props.onOpenOnion}
    />
  );
}

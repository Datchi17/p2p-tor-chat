import { createSignal, Show } from 'solid-js'
import { api, errorText } from '../api'

/** First run: choose a display name and a vault passphrase. */
export default function Setup(props: { onDone: () => void }) {
  const [name, setName] = createSignal('')
  const [pass, setPass] = createSignal('')
  const [pass2, setPass2] = createSignal('')
  const [busy, setBusy] = createSignal(false)
  const [error, setError] = createSignal('')

  const words = () => pass().trim().split(/\s+/).filter(Boolean).length
  const strength = () => {
    const p = pass()
    if (p.length === 0) return { label: 'Tip: use 6 random words chosen with dice (search "Diceware"), never a phrase you have seen elsewhere', ok: false, idle: true }
    if (p.length < 12) return { label: 'Too short (minimum 12 characters)', ok: false, idle: false }
    if (words() >= 6 || p.length >= 30) return { label: 'Strong', ok: true, idle: false }
    if (p.length >= 16) return { label: 'Acceptable — a 6-word passphrase is better', ok: true, idle: false }
    return { label: 'Weak — use 6 random words', ok: true, idle: false }
  }

  const submit = async (e: Event) => {
    e.preventDefault()
    setError('')
    if (pass() !== pass2()) return setError('The passphrases do not match.')
    if (!strength().ok) return setError('Choose a longer passphrase.')
    setBusy(true)
    try {
      await api.createVault(name(), pass())
      setPass('')
      setPass2('')
      props.onDone()
    } catch (err) {
      setError(errorText(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="center-screen">
      <form class="card narrow" onSubmit={submit}>
        <h1>🔐 P2P Chat</h1>
        <p class="muted">
          Everything is stored encrypted on this computer. Your passphrase is the only key — if you forget it,
          your messages cannot be recovered.
        </p>
        <label>
          Your name (shown to your friend)
          <input value={name()} onInput={(e) => setName(e.currentTarget.value)} maxLength={64} required autofocus spellcheck={false} autocorrect="off" autocapitalize="off" autocomplete="off" />
        </label>
        <label>
          Passphrase
          <input type="password" value={pass()} onInput={(e) => setPass(e.currentTarget.value)} autocomplete="new-password" required />
        </label>
        <div class={`hint ${strength().ok || strength().idle ? '' : 'bad'}`}>{strength().label}</div>
        <label>
          Repeat passphrase
          <input type="password" value={pass2()} onInput={(e) => setPass2(e.currentTarget.value)} autocomplete="new-password" required />
        </label>
        <Show when={error()}>
          <div class="error">{error()}</div>
        </Show>
        <button class="primary" disabled={busy()}>
          {busy() ? 'Creating encrypted vault…' : 'Create vault'}
        </button>
      </form>
    </div>
  )
}

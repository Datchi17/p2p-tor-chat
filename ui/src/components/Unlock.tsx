import { createSignal, Show } from 'solid-js'
import { api, errorText } from '../api'

export default function Unlock(props: { onDone: () => void }) {
  const [pass, setPass] = createSignal('')
  const [busy, setBusy] = createSignal(false)
  const [error, setError] = createSignal('')
  const [wipe, setWipe] = createSignal(false)

  const submit = async (e: Event) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.unlock(pass())
      setPass('')
      props.onDone()
    } catch (err) {
      setError(errorText(err))
    } finally {
      setBusy(false)
    }
  }

  const doWipe = async () => {
    await api.panicWipe()
    props.onDone()
  }

  return (
    <div class="center-screen">
      <form class="card narrow" onSubmit={submit}>
        <h1>🔒 P2P Chat</h1>
        <label>
          Passphrase
          <input type="password" value={pass()} onInput={(e) => setPass(e.currentTarget.value)} autofocus required />
        </label>
        <Show when={error()}>
          <div class="error">{error()}</div>
        </Show>
        <button class="primary" disabled={busy()}>
          {busy() ? 'Unlocking…' : 'Unlock'}
        </button>
        <Show
          when={wipe()}
          fallback={
            <button type="button" class="link danger-text" onClick={() => setWipe(true)}>
              Forgot passphrase / destroy everything
            </button>
          }
        >
          <div class="danger-box">
            <p>This permanently destroys all keys and messages on this computer. It cannot be undone.</p>
            <button type="button" class="danger" onClick={doWipe}>
              Destroy everything
            </button>
            <button type="button" class="link" onClick={() => setWipe(false)}>
              Cancel
            </button>
          </div>
        </Show>
      </form>
    </div>
  )
}

import { createSignal, onCleanup, onMount, Show } from 'solid-js'
import { api } from '../api'

/** Screen lock after inactivity. The app stays online; the passphrase is needed to see it again. */
export default function LockOverlay(props: { minutes: number; locked: boolean; setLocked: (v: boolean) => void }) {
  const [pass, setPass] = createSignal('')
  const [error, setError] = createSignal('')
  let last = Date.now()

  onMount(() => {
    const bump = () => (last = Date.now())
    const events = ['mousemove', 'keydown', 'mousedown', 'wheel', 'touchstart']
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }))
    const timer = setInterval(() => {
      if (props.minutes > 0 && !props.locked && Date.now() - last > props.minutes * 60_000) props.setLocked(true)
    }, 5_000)
    onCleanup(() => {
      events.forEach((e) => window.removeEventListener(e, bump))
      clearInterval(timer)
    })
  })

  const unlock = async (e: Event) => {
    e.preventDefault()
    if (await api.verifyPassphrase(pass())) {
      setPass('')
      setError('')
      last = Date.now()
      props.setLocked(false)
    } else {
      setError('Wrong passphrase.')
    }
  }

  return (
    <Show when={props.locked}>
      <div class="overlay opaque">
        <form class="card narrow" onSubmit={unlock}>
          <h2>🔒 Locked</h2>
          <p class="muted small">Still online and receiving messages.</p>
          <input type="password" placeholder="Passphrase" value={pass()} onInput={(e) => setPass(e.currentTarget.value)} autofocus />
          <Show when={error()}>
            <div class="error">{error()}</div>
          </Show>
          <button class="primary">Unlock</button>
        </form>
      </div>
    </Show>
  )
}

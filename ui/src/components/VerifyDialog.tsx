import { createResource, createSignal, For, Show } from 'solid-js'
import { api, errorText, type Contact } from '../api'
import Modal from './Modal'

/** Two distinct random group positions (0–11), chosen fresh every time the dialog opens. */
function pickGroups(): [number, number] {
  const r = new Uint32Array(2)
  for (;;) {
    crypto.getRandomValues(r)
    const a = r[0] % 12
    const b = r[1] % 12
    if (a !== b) return a < b ? [a, b] : [b, a]
  }
}

const ordinal = (i: number) => `group ${i + 1}`

export default function VerifyDialog(props: { contact: Contact; onClose: () => void; onChanged: () => void }) {
  const [groups] = createResource(() => props.contact.id, api.safetyNumber)
  const [ask] = createSignal(pickGroups())
  const [first, setFirst] = createSignal('')
  const [second, setSecond] = createSignal('')
  const [error, setError] = createSignal('')
  const [busy, setBusy] = createSignal(false)

  const verify = async (e: Event) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const [a, b] = ask()
      await api.verifyContact(props.contact.id, [
        [a, first()],
        [b, second()],
      ])
      props.onChanged()
      props.onClose()
    } catch (err) {
      setError(errorText(err))
    } finally {
      setBusy(false)
    }
  }

  const unverify = async () => {
    await api.unverifyContact(props.contact.id)
    props.onChanged()
    props.onClose()
  }

  return (
    <Modal title={`Verify ${props.contact.name}`} onClose={props.onClose}>
      <ol class="steps">
        <li>
          Call {props.contact.name} by <strong>voice or video</strong>: you must recognize them. Never do this by text.
        </li>
        <li>Both of you open this screen. Read the 12 groups to each other and compare every digit.</li>
        <li>
          Then ask {props.contact.name} to read <strong>{ordinal(ask()[0])}</strong> and{' '}
          <strong>{ordinal(ask()[1])}</strong> <em>from their screen</em>, and type what you hear below.
        </li>
      </ol>
      <Show when={groups()} fallback={<p class="muted">Computing…</p>}>
        {(g) => (
          <div class="safety">
            <For each={g()}>
              {(n, i) => (
                <span class={i() === ask()[0] || i() === ask()[1] ? 'ask' : ''} title={ordinal(i())}>
                  {n}
                </span>
              )}
            </For>
          </div>
        )}
      </Show>
      <form class="row gap wrap" onSubmit={verify}>
        <label class="digits">
          {ordinal(ask()[0])} (as they read it)
          <input inputMode="numeric" maxLength={7} value={first()} onInput={(e) => setFirst(e.currentTarget.value)} required />
        </label>
        <label class="digits">
          {ordinal(ask()[1])} (as they read it)
          <input inputMode="numeric" maxLength={7} value={second()} onInput={(e) => setSecond(e.currentTarget.value)} required />
        </label>
        <button class="primary" disabled={busy()}>
          ✅ Verify
        </button>
      </form>
      <Show when={error()}>
        <div class="error">{error()}</div>
      </Show>
      <Show when={props.contact.verified}>
        <button onClick={unverify}>Mark as not verified</button>
      </Show>
      <div class="danger-box">
        <strong>If any digit differs:</strong> do not verify. Someone may have swapped the pairing codes. Delete this
        contact and pair again using a different way to exchange codes.
        <br />
        <strong>Re-pairing rule:</strong> every new code from {props.contact.name} (new computer, reinstall) means a
        fresh live call and this full check again — never accept "it's me, just re-add me" by text.
      </div>
    </Modal>
  )
}

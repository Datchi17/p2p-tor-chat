import { createResource, createSignal, Show } from 'solid-js'
import { api, errorText } from '../api'
import Modal from './Modal'

function svgDataUrl(svg: string) {
  return `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`
}

export default function PairDialog(props: { onClose: () => void; onAdded: (id: number) => void }) {
  const [mine] = createResource(api.myCode)
  const [code, setCode] = createSignal('')
  const [nick, setNick] = createSignal('')
  const [error, setError] = createSignal('')
  const [copied, setCopied] = createSignal(false)
  let mineBox: HTMLTextAreaElement | undefined

  const copy = async () => {
    const c = mine()?.code
    if (!c) return
    try {
      await navigator.clipboard.writeText(c)
    } catch {
      mineBox?.select()
      document.execCommand('copy')
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const add = async (e: Event) => {
    e.preventDefault()
    setError('')
    try {
      const id = await api.addContact(code(), nick().trim() || null)
      props.onAdded(id)
    } catch (err) {
      setError(errorText(err))
    }
  }

  return (
    <Modal title="Pair with a friend" onClose={props.onClose} wide>
      <div class="pair-grid">
        <section>
          <h3>1. Send your code to your friend</h3>
          <p class="muted small">
            It contains only public keys and your onion address, so it's fine to send by email or another messenger.
            Your friend sends you theirs.
          </p>
          <Show when={mine()} fallback={<p class="muted">Loading…</p>}>
            {(m) => (
              <>
                <textarea ref={mineBox} class="code" readOnly rows={5} value={m().code} onFocus={(e) => e.currentTarget.select()} />
                <div class="row gap">
                  <button class="primary" onClick={copy}>
                    {copied() ? 'Copied ✓' : 'Copy my code'}
                  </button>
                </div>
                <details>
                  <summary class="small">Show as QR code</summary>
                  <img class="qr" alt="Pairing QR code" src={svgDataUrl(m().qr_svg)} />
                </details>
              </>
            )}
          </Show>
        </section>
        <form onSubmit={add}>
          <h3>2. Paste your friend's code</h3>
          <textarea
            class="code"
            rows={5}
            placeholder="p2pchat1:…"
            spellcheck={false}
            value={code()}
            onInput={(e) => setCode(e.currentTarget.value)}
            required
          />
          <label>
            Name for this contact (optional)
            <input value={nick()} onInput={(e) => setNick(e.currentTarget.value)} maxLength={64} spellcheck={false} autocorrect="off" autocapitalize="off" autocomplete="off" />
          </label>
          <Show when={error()}>
            <div class="error">{error()}</div>
          </Show>
          <button class="primary">Add contact</button>
          <p class="muted small">
            Next you'll compare a safety number with your friend on a <strong>live voice or video call</strong>. That
            step is what proves nobody swapped the codes.
          </p>
        </form>
      </div>
    </Modal>
  )
}

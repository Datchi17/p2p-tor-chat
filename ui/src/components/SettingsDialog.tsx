import { createResource, createSignal, For, Show } from 'solid-js'
import { api, errorText, type Settings } from '../api'
import Modal from './Modal'

export default function SettingsDialog(props: { onClose: () => void; onWiped: () => void }) {
  const [initial] = createResource(api.settings)
  const [draft, setDraft] = createSignal<Settings | null>(null)
  const s = () => draft() ?? initial()
  const update = (patch: Partial<Settings>) => setDraft({ ...s()!, ...patch })
  const [msg, setMsg] = createSignal('')
  const [oldPass, setOldPass] = createSignal('')
  const [newPass, setNewPass] = createSignal('')
  const [newPass2, setNewPass2] = createSignal('')
  const [passMsg, setPassMsg] = createSignal('')
  const [wipeStep, setWipeStep] = createSignal(0)
  const [log, setLog] = createSignal<string[] | null>(null)

  const save = async () => {
    try {
      await api.setSettings(s()!)
      setMsg('Saved.')
    } catch (e) {
      setMsg(errorText(e))
    }
  }

  const changePass = async (e: Event) => {
    e.preventDefault()
    if (newPass() !== newPass2()) return setPassMsg('The new passphrases do not match.')
    try {
      await api.changePassphrase(oldPass(), newPass())
      setOldPass('')
      setNewPass('')
      setNewPass2('')
      setPassMsg('Passphrase changed. The vault was re-encrypted.')
    } catch (err) {
      setPassMsg(errorText(err))
    }
  }

  const wipe = async () => {
    await api.panicWipe()
    props.onWiped()
  }

  return (
    <Modal title="Settings" onClose={props.onClose} wide>
      <Show when={s()} fallback={<p class="muted">Loading…</p>}>
        {(cur) => (
          <div class="settings">
            <section>
              <h3>Privacy</h3>
              <label class="check">
                <input type="checkbox" checked={cur().read_receipts} onChange={(e) => update({ read_receipts: e.currentTarget.checked })} />
                Send read receipts
              </label>
              <label class="check">
                <input type="checkbox" checked={cur().notifications} onChange={(e) => update({ notifications: e.currentTarget.checked })} />
                Flash the taskbar on new messages (never shows content)
              </label>
              <label>
                Lock the screen after inactivity
                <select value={cur().auto_lock_minutes} onChange={(e) => update({ auto_lock_minutes: Number(e.currentTarget.value) })}>
                  <For each={[[1, '1 minute'], [5, '5 minutes'], [10, '10 minutes'], [30, '30 minutes'], [60, '1 hour'], [0, 'Never']] as [number, string][]}>
                    {([v, l]) => <option value={v}>{l}</option>}
                  </For>
                </select>
              </label>
              <p class="muted small">
                The screen lock hides the app but stays online. Use 🔒 to lock fully: keys are wiped from memory and you
                go offline.
              </p>
            </section>
            <section>
              <h3>Tor bridges</h3>
              <p class="muted small">
                Only needed if Tor is blocked where you are. One bridge line per line. Saving restarts Tor.
              </p>
              <textarea
                class="code"
                rows={3}
                value={cur().bridges.join('\n')}
                placeholder="obfs4 192.0.2.1:443 FINGERPRINT cert=… iat-mode=0"
                spellcheck={false}
                onInput={(e) => update({ bridges: e.currentTarget.value.split('\n') })}
              />
            </section>
            <div class="row gap">
              <button class="primary" onClick={save}>
                Save settings
              </button>
              <span class="muted">{msg()}</span>
            </div>

            <form onSubmit={changePass}>
              <h3>Change passphrase</h3>
              <input type="password" placeholder="Current passphrase" value={oldPass()} onInput={(e) => setOldPass(e.currentTarget.value)} required />
              <input type="password" placeholder="New passphrase (12+ characters)" value={newPass()} onInput={(e) => setNewPass(e.currentTarget.value)} required minLength={12} />
              <input type="password" placeholder="Repeat new passphrase" value={newPass2()} onInput={(e) => setNewPass2(e.currentTarget.value)} required />
              <button>Change passphrase</button>
              <span class="muted small">{passMsg()}</span>
            </form>

            <section>
              <h3>Troubleshooting</h3>
              <button onClick={async () => setLog(await api.torLog())}>Show Tor log</button>
              <Show when={log()}>{(l) => <pre class="log">{l().join('\n') || '(empty)'}</pre>}</Show>
            </section>

            <section class="danger-box">
              <h3>Destroy everything</h3>
              <p class="small">Deletes all keys, contacts and messages from this computer. This cannot be undone.</p>
              <Show when={wipeStep() === 0}>
                <button class="danger" onClick={() => setWipeStep(1)}>
                  Destroy everything…
                </button>
              </Show>
              <Show when={wipeStep() === 1}>
                <button class="danger" onClick={wipe}>
                  Yes, destroy it all now
                </button>{' '}
                <button class="link" onClick={() => setWipeStep(0)}>
                  Cancel
                </button>
              </Show>
            </section>
          </div>
        )}
      </Show>
    </Modal>
  )
}

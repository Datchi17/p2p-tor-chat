import { createMemo, createSignal, For, onCleanup, onMount, Show } from 'solid-js'
import { api, errorText, onCoreEvent, type Contact, type CoreEvent, type Message, type Settings } from '../api'
import Chat from './Chat'
import PairDialog from './PairDialog'
import VerifyDialog from './VerifyDialog'
import SettingsDialog from './SettingsDialog'
import LockOverlay from './LockOverlay'

/** After this many days the app reminds you to update (it never checks online). */
const STALE_AFTER_DAYS = 90

interface Tor {
  progress: number
  ready: boolean
  error: string | null
}

export default function Main(props: { onLocked: () => void }) {
  const [contacts, setContacts] = createSignal<Contact[]>([])
  const [selected, setSelected] = createSignal<number | null>(null)
  const [messages, setMessages] = createSignal<Message[]>([])
  const [tor, setTor] = createSignal<Tor>({ progress: 0, ready: false, error: null })
  const [dialog, setDialog] = createSignal<'pair' | 'verify' | 'settings' | null>(null)
  const [security, setSecurity] = createSignal<{ contact_id: number; message: string } | null>(null)
  const [settings, setSettings] = createSignal<Settings | null>(null)
  const [screenLocked, setScreenLocked] = createSignal(false)
  const [myName, setMyName] = createSignal('')
  const [staleDays, setStaleDays] = createSignal<number | null>(null)

  const current = createMemo(() => contacts().find((c) => c.id === selected()) ?? null)

  const loadContacts = async () => {
    const list = await api.contacts()
    setContacts(list)
    if (selected() === null && list.length > 0) select(list[0].id)
    if (selected() !== null && !list.some((c) => c.id === selected())) {
      setSelected(null)
      setMessages([])
    }
  }

  const select = async (id: number) => {
    setSelected(id)
    setMessages(await api.messages(id, null))
    if (document.hasFocus()) await api.markRead(id)
  }

  const onEvent = (e: CoreEvent) => {
    switch (e.type) {
      case 'tor':
        setTor({ progress: e.progress, ready: e.ready, error: e.error })
        break
      case 'presence':
        setContacts((cs) => cs.map((c) => (c.id === e.contact_id ? { ...c, online: e.online } : c)))
        break
      case 'message': {
        const m = e.message
        if (m.contact_id === selected()) {
          setMessages((ms) => {
            const i = ms.findIndex((x) => x.id === m.id)
            if (i >= 0) return ms.map((x) => (x.id === m.id ? m : x))
            return [...ms, m]
          })
          if (!m.outgoing && m.status === 'unread' && document.hasFocus() && !screenLocked()) void api.markRead(m.contact_id)
        }
        const isNew = m.kind === 'text' || (m.kind === 'file' && m.file?.state === 'receiving' && m.file.done === 0)
        if (!m.outgoing && isNew && (!document.hasFocus() || screenLocked()) && settings()?.notifications) {
          void api.attention()
        }
        break
      }
      case 'deleted':
        if (e.contact_id === selected()) setMessages((ms) => ms.filter((m) => !e.ids.includes(m.id)))
        break
      case 'contacts':
        void loadContacts()
        break
      case 'security':
        setSecurity({ contact_id: e.contact_id, message: e.message })
        break
      case 'locked':
        props.onLocked()
        break
    }
  }

  onMount(async () => {
    const un = await onCoreEvent(onEvent)
    onCleanup(un)
    setSettings(await api.settings())
    setMyName((await api.myCode()).name)
    const age = await api.buildAgeDays()
    if (age !== null && age >= STALE_AFTER_DAYS) setStaleDays(age)
    await loadContacts()
    const onFocus = () => {
      const id = selected()
      if (id !== null && !screenLocked()) void api.markRead(id)
    }
    window.addEventListener('focus', onFocus)
    onCleanup(() => window.removeEventListener('focus', onFocus))
  })

  const lockNow = async () => {
    await api.lock()
    props.onLocked()
  }

  const totalUnread = createMemo(() => contacts().reduce((n, c) => n + c.unread, 0))
  createMemo(() => {
    document.title = totalUnread() > 0 ? `(${totalUnread()}) P2P Chat` : 'P2P Chat'
  })

  return (
    <div class="app">
      <aside class="sidebar">
        <div class="sidebar-head">
          <div class="me" title="This device">
            {myName()}
          </div>
          <div class="row gap">
            <button class="icon" title="Settings" onClick={() => setDialog('settings')}>
              ⚙
            </button>
            <button class="icon" title="Lock and go offline" onClick={lockNow}>
              🔒
            </button>
          </div>
        </div>
        <div class="contacts">
          <For each={contacts()} fallback={<p class="muted pad">No contacts yet. Pair with your friend to start.</p>}>
            {(c) => (
              <button class={`contact ${selected() === c.id ? 'active' : ''}`} onClick={() => select(c.id)}>
                <span class={`dot ${c.online ? 'on' : ''}`} title={c.online ? 'Reachable now' : 'Offline'} />
                <span class="contact-name">{c.name}</span>
                <Show when={!c.verified}>
                  <span class="badge warn" title="Not verified">!</span>
                </Show>
                <Show when={c.queued > 0}>
                  <span class="badge" title="Messages waiting to be delivered">
                    🕓{c.queued}
                  </span>
                </Show>
                <Show when={c.unread > 0}>
                  <span class="badge accent">{c.unread}</span>
                </Show>
              </button>
            )}
          </For>
        </div>
        <button class="primary pair-btn" onClick={() => setDialog('pair')}>
          + Pair with a friend
        </button>
      </aside>

      <main class="main">
        <Show when={staleDays()}>
          {(d) => (
            <div class="banner warn">
              <strong>This version is {d()} days old.</strong> Updates bring security fixes for Tor and the
              encryption. Get the newest installer from the person who gave you the app, and check its
              fingerprint on a call before installing.
              <button class="link" onClick={() => setStaleDays(null)}>
                Dismiss
              </button>
            </div>
          )}
        </Show>
        <Show when={security()}>
          {(s) => (
            <div class="banner danger">
              <strong>Security warning:</strong> {s().message}
              <button class="link" onClick={() => setSecurity(null)}>
                Dismiss
              </button>
            </div>
          )}
        </Show>
        <Show
          when={current()}
          fallback={
            <div class="empty">
              <p>Select a conversation, or pair with a friend.</p>
            </div>
          }
        >
          {(c) => (
            <Chat
              contact={c()}
              messages={messages()}
              onVerify={() => setDialog('verify')}
              onChanged={loadContacts}
              onSend={async (text) => {
                try {
                  await api.sendText(c().id, text)
                  return null
                } catch (e) {
                  return errorText(e)
                }
              }}
              onLoadOlder={async () => {
                const first = messages()[0]
                if (!first) return
                const older = await api.messages(c().id, first.ts)
                setMessages((ms) => [...older, ...ms])
              }}
            />
          )}
        </Show>
        <footer class="statusbar">
          <Show
            when={tor().ready}
            fallback={
              <span class={tor().error ? 'bad' : ''}>
                {tor().error ? `🧅 Tor error: ${tor().error}` : `🧅 Connecting to Tor… ${tor().progress}%`}
              </span>
            }
          >
            <span>🧅 Tor connected</span>
          </Show>
          <span>🔐 End-to-end encrypted (Signal PQXDH)</span>
        </footer>
      </main>

      <Show when={dialog() === 'pair'}>
        <PairDialog
          onClose={() => setDialog(null)}
          onAdded={async (id) => {
            await loadContacts()
            await select(id)
            setDialog('verify')
          }}
        />
      </Show>
      <Show when={dialog() === 'verify' && current()}>
        {(_) => <VerifyDialog contact={current()!} onClose={() => setDialog(null)} onChanged={loadContacts} />}
      </Show>
      <Show when={dialog() === 'settings'}>
        <SettingsDialog
          onClose={async () => {
            setDialog(null)
            setSettings(await api.settings())
          }}
          onWiped={props.onLocked}
        />
      </Show>
      <LockOverlay
        minutes={settings()?.auto_lock_minutes ?? 10}
        locked={screenLocked()}
        setLocked={setScreenLocked}
      />
    </div>
  )
}

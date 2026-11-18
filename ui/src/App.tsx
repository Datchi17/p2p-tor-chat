import { createSignal, Match, onCleanup, onMount, Switch } from 'solid-js'
import { api, onCoreEvent, type AppState } from './api'
import Setup from './components/Setup'
import Unlock from './components/Unlock'
import Main from './components/Main'

export default function App() {
  const [state, setState] = createSignal<AppState | null>(null)
  const refresh = async () => setState(await api.state())

  onMount(async () => {
    await refresh()
    const un = await onCoreEvent((e) => {
      if (e.type === 'locked') void refresh()
    })
    onCleanup(un)
  })

  return (
    <Switch>
      <Match when={state() === 'no_vault'}>
        <Setup onDone={refresh} />
      </Match>
      <Match when={state() === 'locked'}>
        <Unlock onDone={refresh} />
      </Match>
      <Match when={state() === 'unlocked'}>
        <Main onLocked={refresh} />
      </Match>
    </Switch>
  )
}

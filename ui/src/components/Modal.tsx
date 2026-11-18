import type { JSX } from 'solid-js'

export default function Modal(props: { title: string; onClose: () => void; children: JSX.Element; wide?: boolean }) {
  return (
    <div class="overlay" onClick={(e) => e.target === e.currentTarget && props.onClose()}>
      <div class={`card modal ${props.wide ? 'wide' : ''}`} role="dialog" aria-label={props.title}>
        <div class="modal-head">
          <h2>{props.title}</h2>
          <button class="icon" onClick={props.onClose} title="Close">
            ✕
          </button>
        </div>
        {props.children}
      </div>
    </div>
  )
}

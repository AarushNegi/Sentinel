import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import BlueEvidenceCard from './BlueEvidenceCard'

const evidence = {
  id: 'EV-HEADERS',
  title: 'Email header analysis',
  category: 'header',
  preservable: true,
  preserved: false,
  content: {
    summary: 'Authentication results.',
    fields: [['SPF', 'FAIL'], ['Reply-To', 'collect@example.test']],
    columns: ['Hop', 'From'],
    rows: [['1', 'mail.lookalike.test']],
    verdict: 'Authentication failed.',
  },
}

describe('BlueEvidenceCard', () => {
  it('renders summary, fields, table and verdict', () => {
    render(<BlueEvidenceCard evidence={evidence} />)
    expect(screen.getByText('Email header analysis')).toBeInTheDocument()
    expect(screen.getByText('SPF')).toBeInTheDocument()
    expect(screen.getByText('FAIL')).toBeInTheDocument()
    expect(screen.getByText('mail.lookalike.test')).toBeInTheDocument()
    expect(screen.getByText('Authentication failed.')).toBeInTheDocument()
  })

  it('treats scenario text as untrusted: HTML is shown as text, never injected', () => {
    const hostile = {
      ...evidence,
      content: {
        summary: '<img src=x onerror="window.__pwned=1">',
        fields: [['Link', 'https://evil.test/<script>alert(1)</script>']],
        columns: [],
        rows: [],
      },
    }
    const { container } = render(<BlueEvidenceCard evidence={hostile} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('a')).toBeNull()
    expect(screen.getByText(/onerror/)).toBeInTheDocument()
    expect(window.__pwned).toBeUndefined()
  })

  it('offers preservation and reports the chosen evidence id', async () => {
    const onPreserve = vi.fn()
    render(<BlueEvidenceCard evidence={evidence} onPreserve={onPreserve} />)
    await userEvent.click(screen.getByRole('button', { name: 'Preserve' }))
    expect(onPreserve).toHaveBeenCalledWith('EV-HEADERS')
  })

  it('shows preserved evidence as preserved, without a button', () => {
    render(<BlueEvidenceCard evidence={{ ...evidence, preserved: true }} onPreserve={() => {}} />)
    expect(screen.getByText(/PRESERVED/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Preserve' })).toBeNull()
  })

  it('does not offer preservation for non-forensic evidence', () => {
    render(<BlueEvidenceCard evidence={{ ...evidence, preservable: false }} onPreserve={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Preserve' })).toBeNull()
  })
})

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test } from 'vitest'
import SubmittedUrl from './SubmittedUrl.jsx'

const urlElement = (url) => screen.getByText(url)

describe('SubmittedUrl', () => {
  test('a URL of 80 code points has no toggle', () => {
    const url = 'example.com/' + 'a'.repeat(68)
    const { container } = render(<SubmittedUrl url={url} />)
    expect(Array.from(url)).toHaveLength(80)
    expect(urlElement(url)).toHaveTextContent(url)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(container.querySelector('a')).toBeNull()
  })

  test('80 emoji count as 80 code points, so there is still no toggle', () => {
    render(<SubmittedUrl url={'😀'.repeat(80)} />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  test('a long URL toggles between clamped and full, always keeping the full text', async () => {
    const user = userEvent.setup()
    const url = 'javascript:alert(1)//' + 'x'.repeat(100)
    const { container } = render(<SubmittedUrl url={url} />)

    const toggle = screen.getByRole('button', { name: 'Show full address' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveAttribute('aria-controls', urlElement(url).id)
    expect(urlElement(url).textContent).toBe(url)

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(toggle).toHaveAccessibleName('Show less')
    expect(urlElement(url).textContent).toBe(url)

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveAccessibleName('Show full address')
    expect(container.querySelector('a')).toBeNull()
  })
})

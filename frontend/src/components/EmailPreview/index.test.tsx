import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import EmailPreview from './index';

afterEach(cleanup);

it('isolates mail HTML without scripts, same-origin access or external content', () => {
  const html = '<h1>日报</h1><script>parent.location="https://example.invalid"</script><img src="https://example.invalid/image">';
  render(<EmailPreview html={html} />);
  const frame = screen.getByTitle('邮件内容预览');
  expect(frame).toHaveAttribute('sandbox', '');
  expect(frame).toHaveAttribute('referrerpolicy', 'no-referrer');
  expect(frame.getAttribute('srcdoc')).toMatch(/^<meta http-equiv="Content-Security-Policy"/);
  expect(frame.getAttribute('srcdoc')).toContain("default-src 'none'");
  expect(screen.queryByRole('heading', { name: '日报' })).not.toBeInTheDocument();
});

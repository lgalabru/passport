import { expect, test } from '@playwright/test';

test('landing page presents the product without reading anything', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Prove it.Don’t show it.');
  // The illustrations are pictures of the app, not control surfaces.
  await expect(page.getByRole('button')).toHaveCount(0);
  await page.locator('#iphone').scrollIntoViewIfNeeded();
  await expect(page.getByRole('heading', { name: 'Tap your passport.' })).toBeVisible();
  await page.locator('#features').scrollIntoViewIfNeeded();
  await expect(page.getByText('Share the answer. Keep the passport.')).toBeVisible();
  await page.locator('#verifiers').scrollIntoViewIfNeeded();
  await expect(
    page.getByRole('heading', { name: 'Ask a question. Get a proof back.' }),
  ).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
});

test('the story follows the scroll to the shared proof', async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => {
    const story = document.querySelector<HTMLElement>('#iphone')!;
    const top = story.getBoundingClientRect().top + window.scrollY;
    window.scrollTo({ top: top + (story.offsetHeight - window.innerHeight) * 0.95 });
  });
  await expect(page.getByRole('heading', { name: 'One fact leaves.' })).toBeVisible();
});

test('the experimental status is stated plainly', async ({ page }) => {
  await page.goto('/');
  await page.getByText('Can I rely on it today?', { exact: true }).click();
  await expect(page.getByText(/nothing here has been audited/)).toBeVisible();
  await expect(page.getByRole('link', { name: /Experimental/ })).toHaveAttribute(
    'href',
    'https://github.com/lgalabru/passport',
  );
  await page.locator('#status').scrollIntoViewIfNeeded();
  await expect(
    page.getByRole('heading', { name: 'Not audited. Not for anything real.' }),
  ).toBeInViewport();
});

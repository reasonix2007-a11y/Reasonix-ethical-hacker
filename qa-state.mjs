export default async function run(page) {
  await page.waitForTimeout(4000);
  return await page.evaluate(() => JSON.stringify({
    hasState: typeof state !== 'undefined',
    hasEnterApp: typeof enterApp,
    authHidden: document.querySelector('#auth-gate')?.classList.contains('hidden')
  }));
}

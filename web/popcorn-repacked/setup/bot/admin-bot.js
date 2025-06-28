import puppeteer from 'puppeteer';

const CHROME_EXECUTABLE_PATH = '/usr/bin/google-chrome';

const BASE_URL = 'http://127.0.0.1'; //process.env.BASE_URL;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME_EXECUTABLE_PATH,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const page = await browser.newPage();
  page.on('dialog', async (dialog) => {
    console.log(`[BOT] Dismissing dialog: ${dialog.message()}`);
    await dialog.accept(); // or dialog.dismiss() if needed
  });

  //console.log(`[BOT] Is sleaping for 20 secs`);
  //await new Promise(r => setTimeout(r, 20 * 1000));

  try {
    // One-time login
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle0' });
    await page.type('input[name="username"]', ADMIN_USERNAME);
    await page.type('input[name="password"]', ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForNavigation({ waitUntil: 'networkidle0' });

    console.log(`[BOT] Logged in as admin`);

    // Visit loop
    const visitPages = async () => {
      //await new Promise(r => setTimeout(r, 5 * 1000));
      await page.goto(`${BASE_URL}/movies`, { waitUntil: 'networkidle0' });

      // Fetch list of movie IDs
      const movieLinks = await page.$$eval('a[href^="/movies/"]', links =>
        links.map(link => link.href).filter(href => /\d+$/.test(href))
      );

      // Visit all known movie 
      for (const url of movieLinks) {
        try {
          //await new Promise(r => setTimeout(r, 5 * 1000));
          console.log(`Visiting ${url}`);
          await page.goto(url, { waitUntil: 'networkidle0' });

          const externalLinks = await page.evaluate(() => {
            const reviews = Array.from(document.querySelectorAll('.review-card'));
            const urlRegex = /(https?:\/\/[^\s]+)/g;
            const links = [];
        
            for (const review of reviews) {
              const matches = review.textContent.match(urlRegex);
              if (matches) {
                links.push(...matches);
              }
            }
        
            return links;
          });
        
          for (const link of externalLinks) {
            console.log(`Clicking (visiting) external link in review: ${link}`);
            try {
              const newPage = await browser.newPage();
              await newPage.goto(link, { waitUntil: 'domcontentloaded', timeout: 10000 });
              await newPage.close();
            } catch (err) {
              console.error(`Failed to visit ${link}:`, err.message);
            }
          }

        } catch (err) {
          console.log(`[BOT] Failed to visit ${url}: ${err.message}`);
        }
      }
    };

    while(true){
      await visitPages(); // First run immediately
    }
    

  } catch (err) {
    console.error('[BOT] Error:', err);
    await browser.close();
  }
})();
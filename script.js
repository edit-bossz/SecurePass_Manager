const mdConverter = new showdown.Converter({
    tables: true,
    simplifiedAutoLink: true,
    strikethrough: true,
    tasklists: true
  });
  
  // Then modify the fetchReleases function:
  async function fetchReleases() {
    try {
      const response = await fetch('https://api.github.com/repos/edit-bossz/SecurePass_Manager/releases');
      const releases = await response.json();
  
      // Featured releases (3)
      const featuredContainer = document.getElementById('releases-container');
      if(featuredContainer) {
        featuredContainer.innerHTML = releases.slice(0,3).map(release => `
          <div class="release-card">
            <h3>${release.tag_name}</h3>
            <p>${new Date(release.published_at).toLocaleDateString()}</p>
            <div class="assets">
              ${release.assets.map(asset => `
                <a href="${asset.browser_download_url}" download>${asset.name}</a>
              `).join('')}
            </div>
            <div class="markdown-body" style="margin-top: 1rem; font-size: 0.9em;">
              ${mdConverter.makeHtml(release.body.split('\n').slice(0, 3).join('\n') + '...')}
            </div>
          </div>
        `).join('');
      }
  
    } catch (error) {
      console.error('Error fetching releases:', error);
    }
  }
  
// Theme Toggle with persistence
const themeToggle = document.getElementById('theme-toggle');
const sunIcon = document.getElementById('sun-icon');
const moonIcon = document.getElementById('moon-icon');

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', newTheme);
  sunIcon.style.display = newTheme === 'light' ? 'block' : 'none';
  moonIcon.style.display = newTheme === 'dark' ? 'block' : 'none';
  localStorage.setItem('theme', newTheme);
}

themeToggle.addEventListener('click', toggleTheme);

const savedTheme = localStorage.getItem('theme') || 
  (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
document.documentElement.setAttribute('data-theme', savedTheme);
sunIcon.style.display = savedTheme === 'light' ? 'block' : 'none';
moonIcon.style.display = savedTheme === 'dark' ? 'block' : 'none';

// Fetch and update releases
async function fetchReleases() {
  try {
    const response = await fetch('https://api.github.com/repos/edit-bossz/SecurePass_Manager/releases');
    const releases = await response.json();

    // Featured releases (3)
    const featuredContainer = document.getElementById('releases-container');
    if(featuredContainer) {
      featuredContainer.innerHTML = releases.slice(0,3).map(release => `
        <div class="release-card">
          <h3>${release.tag_name}</h3>
          <p>${new Date(release.published_at).toLocaleDateString()}</p>
          <div class="assets">
            ${release.assets.map(asset => `
              <a href="${asset.browser_download_url}" download>${asset.name}</a>
            `).join('')}
          </div>
        </div>
      `).join('');
    }

    // All releases
    const allReleasesContainer = document.getElementById('all-releases-container');
    if(allReleasesContainer) {
      allReleasesContainer.innerHTML = releases.map(release => `
        <div class="detailed-release-card">
          <h3>${release.tag_name} - ${release.name}</h3>
          <p class="release-date">Published on ${new Date(release.published_at).toLocaleDateString()}</p>
          <div class="release-body">${release.body}</div>
          <div class="assets">
            ${release.assets.map(asset => `
              <a href="${asset.browser_download_url}" download>${asset.name}</a>
            `).join('')}
          </div>
        </div>
      `).join('');
    }

  } catch (error) {
    console.error('Error fetching releases:', error);
  }
}

// Fetch latest release for download button
async function fetchLatestRelease() {
  try {
    const response = await fetch('https://api.github.com/repos/edit-bossz/SecurePass_Manager/releases/latest');
    const release = await response.json();
    const exeAsset = release.assets.find(asset => asset.name.endsWith('.exe'));
    const exeBtn = document.getElementById('exe-download');
    if (exeAsset && exeBtn) {
      exeBtn.href = exeAsset.browser_download_url;
      exeBtn.textContent = exeAsset.name;
      exeBtn.download = "";
    } else if(exeBtn) {
      exeBtn.textContent = "Latest Release Unavailable";
      exeBtn.style.pointerEvents = 'none';
      exeBtn.style.opacity = '0.6';
    }
  } catch (error) {
    console.error("Error fetching latest release:", error);
    const exeBtn = document.getElementById('exe-download');
    if(exeBtn) exeBtn.textContent = "Error fetching release";
  }
}

// Python download handler
document.getElementById('python-download')?.addEventListener('click', async function(e) {
  e.preventDefault();
  const url = "https://raw.githubusercontent.com/edit-bossz/SecurePass_Manager/main/main.pyw";
  try {
    const response = await fetch(url);
    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = "main.pyw";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);
  } catch (err) {
    console.error('Download failed', err);
  }
});

// Initial fetches
fetchLatestRelease();
fetchReleases();
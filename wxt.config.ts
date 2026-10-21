import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  modules: ['@wxt-dev/module-vue'],
  // MV3 for both Chrome and Firefox so `optional_host_permissions` and
  // `scripting.registerContentScripts` behave the same way on each.
  manifestVersion: 3,
  manifest: {
    // GitLab's trademark guidelines require that a third-party extension not
    // lead with the GitLab name and use only the "… for GitLab" or "GitLab
    // Compatible" form. The non-affiliation notice they also require lives in
    // the store listing, the README and the options page.
    name: 'Merge Request Security Widget for GitLab',
    description:
      'Renders the security report artifacts your merge request pipeline already produces as a summary on the merge request page.',
    permissions: ['storage', 'scripting', 'activeTab'],
    // gitlab.com is granted up front; self-managed instances are added by the
    // user from the options page and granted through the optional permission.
    host_permissions: ['*://gitlab.com/*'],
    optional_host_permissions: ['*://*/*'],
    action: {
      default_title: 'Merge Request Security Widget for GitLab',
    },
    // Firefox requires a stable extension id for MV3.
    browser_specific_settings: {
      gecko: {
        id: 'security-widget-for-gitlab@local',
        strict_min_version: '128.0',
        // Required by AMO for new submissions. Everything is fetched from the
        // user's own GitLab instance and kept in local storage; nothing is
        // transmitted to us or any third party.
        data_collection_permissions: {
          required: ['none'],
        },
      },
    },
  },
});

# Privacy Policy

_Merge Request Security Widget for GitLab_ — last updated: 2026-10-24

## Summary

The extension does not collect, transmit, sell or share any personal data. It has no server, no analytics and no tracking. Everything it does happens in your browser, between you and your own GitLab instance.

## What the extension accesses

On a GitLab merge request page, the extension calls the GitLab API of that same instance. These requests use your existing GitLab session and fetch:

- merge request and pipeline metadata, such as the head pipeline, the target branch and its jobs
- the security report artifacts those pipelines produced, for example SAST and secret detection reports

This data is processed only in your browser so the summary can be shown on the page. It is kept in memory while the page is open. It is not stored, and it is not sent anywhere other than the GitLab instance it came from.

The extension never reads, stores or transmits your GitLab password, session cookies or access tokens. The browser attaches your existing session to the requests, just as it does for GitLab's own pages.

## What the extension stores

The extension uses the browser's extension storage (`storage.sync`) to keep:

- the list of self-managed GitLab instances you have enabled (their origins, e.g. `https://gitlab.example.com`)
- your display settings for the widget

If you are signed in to your browser with sync turned on, your browser may sync these settings across your devices. That is handled by your browser vendor, not by this extension. Removing the extension deletes this data.

## Permissions

- **Host access** applies to gitlab.com and to any self-managed instance you explicitly enable. The extension uses it only to show the widget on that instance and to fetch the reports described above.
- **`storage`** saves the settings described above.
- **`scripting`** shows the widget on self-managed instances you enable.
- **`activeTab`** lets the popup check whether the current tab is a GitLab instance. It is used only when you open the popup.

## Third parties

The extension sends no data to the developer or to any third party. The only network requests it makes go to the GitLab instance you are viewing. How that instance handles data is governed by its operator's privacy policy, for example GitLab Inc. for gitlab.com.

This extension is not affiliated with, endorsed, sponsored or approved by GitLab Inc.

## Changes

If this policy changes, the updated version will be published at this location with a new date.

## Contact

Questions about this policy: robin.kehl@singular-it.de

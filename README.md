# Openfort Technical Take-Home Assessment

## Overview

Welcome to the Openfort take-home assessment! At Openfort, we're building the next generation of wallet tooling. This assessment will evaluate your technical abilities in our focus areas.

## The Challenge: PostEvent OSINT Chrome Extension

### Background

PostEvent is a fictional Security Operations Center (SOC) as a Service that provides 24/7/365 monitoring and threat response. Their security engineers are looking to streamline their workflow by creating a Chrome extension that can quickly gather open-source intelligence (OSINT) on IP addresses from multiple sources.

### Assessment Goal

Your task is to implement a Chrome extension that enables PostEvent's security operators to:

1. Input an IP address via a Chrome extension popup
2. Automatically collect threat intelligence from multiple sources via interactive browser automation (Do not use the offical API's provided by these vendors):
   - VirusTotal
   - IPInfo
   - AbuseIPDB
3. Display the aggregated information in an intuitive, operator-friendly format

## Technical Requirements

### Chrome DevTools Protocol (CDP) Implementation

The core of this challenge is to build a system similar to Playwright's architecture but focused on security intelligence gathering. You'll need to:

1. Implement a series of modular commands using the Chrome DevTools Protocol via `chrome.debugger`
2. Compose these commands into reusable library functions
3. Use these functions to automate the OSINT data collection workflow

Think of how Playwright's `context.newPage()` abstracts multiple CDP commands into a single, easy-to-use function. Your implementation should follow a similar pattern of abstraction and composability.

### Boilerplate Code

We've provided some boilerplate code to get you started, including:
- Basic extension structure
- Manifest file
- Popup UI skeleton

Your job is to implement the CDP-based automation library and integrate it with the extension interface.

## Technical Background

### Playwright
[Playwright](https://playwright.dev/) is a modern automation framework for browser testing and web scraping. What makes Playwright powerful is its architecture:

- It provides a high-level API that abstracts away complex browser interactions
- Under the hood, it communicates with browsers using the Chrome DevTools Protocol
- It composes multiple low-level CDP commands into intuitive functions like `page.goto()` or `page.click()`

For example, when you call `page.click(selector)`, Playwright executes multiple CDP commands to:
1. Find the element in the DOM
2. Calculate its position
3. Simulate a mouse move
4. Trigger click events

This abstraction makes browser automation both powerful and developer-friendly.

### Chrome DevTools Protocol (CDP)
The [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/) provides a set of methods and events for instrumenting, inspecting, debugging, and profiling Chromium-based browsers. It's the underlying protocol that powers Chrome DevTools.

CDP allows for:
- DOM manipulation
- Network monitoring and interception
- JavaScript execution
- Page navigation and interaction
- And much more

Each CDP domain (like Network, DOM, Runtime) contains specific commands and events. For example, `Page.navigate` instructs the browser to navigate to a URL, while `Runtime.evaluate` executes JavaScript in the page context.

### chrome.debugger API
The `chrome.debugger` API is Chrome's extension interface to the Chrome DevTools Protocol. It allows extensions to:

- Connect to tabs or background pages
- Send CDP commands
- Receive CDP events and responses

Unlike the DevTools application or Playwright, which use WebSockets to communicate with CDP, `chrome.debugger` is a JavaScript API accessible directly from extension code. This makes it particularly powerful for extensions that need to interact with or automate browser behavior.

Key functions include:
- `chrome.debugger.attach()`: Connect to a tab
- `chrome.debugger.sendCommand()`: Send CDP commands
- `chrome.debugger.detach()`: Disconnect from a tab

### Chrome Extension Structure
The extension in this assessment follows the standard Chrome extension architecture for Manifest V3:

- **manifest.json**: Defines metadata, permissions, and resources for the extension
- **background.js**: A service worker that runs in the background
- **popup/**: Contains the UI that appears when clicking the extension icon
  - **popup.html**: The HTML structure of the popup
  - **popup.js**: JavaScript that controls the popup's functionality
  - **popup.css**: Styling for the popup
- **icons/**: Extension icons in various sizes

The workflow for this extension will be:
1. User clicks the extension icon, opening the popup
2. User enters an IP address in the popup
3. The popup communicates with the background service worker
4. The background service worker uses `chrome.debugger` to automate browser interactions
    4.1. The background service worker creates a non active tab for each of the data sources (VirusTotal, IPinfo, AbuseDB IP)
    4.2. The background service worker executes a series of CDP commands that extract the assoicated information
    4.3. The background service worker stores the desired information within chrome local storage
    4.4. The service workers finish
6. Results are returned to the popup for display via a dynamic popup based on the return state of the information

Your challenge is to implement the CDP-based automation in the background service worker and create the data collection and display functionality in the popup.

## Evaluation Criteria

We'll evaluate your submission based on:

1. **Functionality**: Does the extension work as expected?
2. **Code Quality**: Is your code well-structured, modular, and maintainable?
3. **Error Handling**: How does your solution handle edge cases and errors?
4. **Performance**: Is the solution efficient?
5. **UX Taste**: How intuitive and compelling is the interface for security operators?
6. **Information Extraction**: Do you collect the relevent threat and geolocation information from the target websites?

## Submission Guidelines

1. Git clone this repository
2. Implement your solution
3. Submit a .zip file to jaume@openfort.xyz of your program
4. Include a brief write-up explaining your approach, any challenges you faced, and how you overcame them

## Time Expectation

We expect this assessment to take approximately 4 hours to complete. Quality is more important than speed, so take the time you need to deliver a program you're proud of. If you do not finish within the 4 hours, that's completely fine - we'd love to see your progress regardless.

Good luck, and we look forward to seeing your work!

## Sources and Further Reading

For more information on the technologies used in this assessment, refer to these resources:

- [Playwright Official Documentation](https://playwright.dev/) - Learn about Playwright's architecture, capabilities, and API.
- [Chrome DevTools Protocol Documentation](https://chromedevtools.github.io/devtools-protocol/) - The official documentation for CDP.
- [Playwright Introduction Guide](https://www.checklyhq.com/learn/playwright/what-is-playwright/) - A beginner's guide to Playwright automation.
- [Playwright GitHub Repository](https://github.com/microsoft/playwright) - The open-source repository with examples and code snippets.
- [Chrome Extensions Documentation](https://developer.chrome.com/docs/extensions/) - Official documentation for Chrome extension development.
- [Chrome Debugger API](https://developer.chrome.com/docs/extensions/reference/debugger/) - Documentation for the chrome.debugger API used in this assessment.

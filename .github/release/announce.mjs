// Announces a published release on Slack through semantic-release-slack-bot,
// as semantic-release would in its success step: semantic-release runs before
// the build, and leaves a draft, which the Release workflow publishes.
//
// Usage: node announce.mjs [--dry-run] RELEASE_JSON, the release as
// `gh release view --json tagName,body,isPrerelease` prints it. Posts to the
// incoming webhook of SLACK_WEBHOOK; with --dry-run, prints the message that
// it would post.
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import slack from "semantic-release-slack-bot";

const pluginConfig = {
  packageName: "tsigoat",
  notifyOnSuccess: true,
  notifyOnFail: false,
  markdownReleaseNotes: true,
};

const args = process.argv.slice(2);
const dryRun = args[0] === "--dry-run";
const file = dryRun ? args[1] : args[0];
if (!file) {
  console.error("usage: node announce.mjs [--dry-run] RELEASE_JSON");
  process.exit(2);
}
const release = JSON.parse(readFileSync(file, "utf8"));
const repository = process.env.GITHUB_REPOSITORY || "enix/tsigoat";
const server = process.env.GITHUB_SERVER_URL || "https://github.com";

// The dry run posts to a local server, which prints the message and answers
// as Slack does. The plugin reads its webhook from the environment of the
// process.
let local;
if (dryRun) {
  local = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      console.log(JSON.stringify(JSON.parse(body), null, 2));
      response.end("ok");
    });
  });
  await new Promise((resolve) => local.listen(0, "127.0.0.1", resolve));
  process.env.SLACK_WEBHOOK = `http://127.0.0.1:${local.address().port}/`;
  delete process.env.SLACK_TOKEN;
}

const context = {
  env: process.env,
  logger: console,
  branch: { name: release.isPrerelease ? "main" : "release" },
  options: { repositoryUrl: `${server}/${repository}` },
  nextRelease: {
    version: release.tagName.replace(/^v/, ""),
    gitTag: release.tagName,
    notes: release.body || "",
  },
};

try {
  await slack.verifyConditions(pluginConfig, context);
  await slack.success(pluginConfig, context);
} finally {
  local?.close();
}

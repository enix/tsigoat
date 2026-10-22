// A semantic-release plugin for the Tag a release workflow. It refuses a
// version that no stable version precedes, which semantic-release would make
// 1.0.0: the first stable version is tagged by hand. Then it hands the next
// version to the workflow: the tag and the version as step outputs, and the
// notes in the summary of the run, dry runs included.
import { appendFileSync } from "node:fs";

function append(file, text) {
  if (file) {
    appendFileSync(file, text);
  }
}

export async function verifyRelease(pluginConfig, { lastRelease, nextRelease }) {
  if (!lastRelease.version) {
    throw new Error(
      `No stable version precedes ${nextRelease.gitTag}, which semantic-release starts from 1.0.0: ` +
        "the first stable version is tagged by hand, as the Releases section of CONTRIBUTING.md tells.",
    );
  }
}

// After @semantic-release/release-notes-generator, which wrote the notes so
// far; this plugin adds none.
export async function generateNotes(pluginConfig, { env, nextRelease, options }) {
  append(
    env.GITHUB_OUTPUT,
    [
      `tag=${nextRelease.gitTag}`,
      `version=${nextRelease.version}`,
      `prerelease=${nextRelease.channel ? "true" : "false"}`,
      `dry-run=${options.dryRun ? "true" : "false"}`,
      "",
    ].join("\n"),
  );
  const verb = options.dryRun ? "would tag" : "tags";
  append(
    env.GITHUB_STEP_SUMMARY,
    `semantic-release ${verb} ${nextRelease.gitTag}, with these notes:\n\n${nextRelease.notes}\n`,
  );
  return "";
}

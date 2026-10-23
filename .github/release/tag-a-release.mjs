// A semantic-release plugin that hands the next version to the Tag a release
// workflow: the tag and the version as step outputs, and the notes in the
// summary of the run, dry runs included.
import { appendFileSync } from "node:fs";

function append(file, text) {
  if (file) {
    appendFileSync(file, text);
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

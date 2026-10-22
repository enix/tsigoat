// semantic-release, which the Tag a release workflow runs: it computes the
// next version from the Conventional Commits, pushes its tag and leaves a
// draft GitHub release with its notes. The Release workflow then builds on
// the tag, attaches the artifacts to the draft, publishes it and announces
// it. Its packages are pinned in .github/release. JavaScript rather than
// JSON for notesPattern, a function.

// conventional-commits-parser matches its note pattern case-insensitively,
// at the start of every line of a body: a wrapped line that starts with the
// words "breaking change" would make a breaking change. The footer of the
// convention is upper case.
const parserOpts = {
  notesPattern: (keywords) => new RegExp(`^[\\s|*]*(${keywords})[:\\s]+(.*)`),
};

// The sections of the notes, in this order; the other types stay out of
// them, but for their breaking changes.
const types = [
  { type: "security", section: "Security Updates" },
  { type: "feat", section: "Features" },
  { type: "fix", section: "Bug Fixes" },
  { type: "perf", section: "Performance" },
  { type: "deps", section: "Dependencies" },
  { type: "revert", section: "Reverts" },
  { type: "docs", section: "Documentation" },
];

export default {
  branches: [
    // The stable versions, vX.Y.Z: `release` moves forward to a commit of
    // main that a release candidate tested.
    "release",
    // The release candidates, vX.Y.Z-rc.N.
    { name: "main", prerelease: "rc" },
  ],
  tagFormat: "v${version}",
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        parserOpts,
        releaseRules: [
          // While tsigoat is in 0.x, a breaking change makes a minor
          // version; 1.0.0 drops this rule.
          { breaking: true, release: "minor" },
          { type: "security", release: "patch" },
          { type: "deps", release: "patch" },
        ],
      },
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "conventionalcommits",
        parserOpts,
        presetConfig: { types },
      },
    ],
    [
      "@semantic-release/github",
      {
        // The Release workflow publishes the draft once every artifact is
        // attached, then announces it on Slack.
        draftRelease: true,
        // Comments and labels would point to a draft. A failure shows in
        // the run of the workflow, which a maintainer dispatched.
        successCommentCondition: false,
        failCommentCondition: false,
        releasedLabels: false,
      },
    ],
    "./.github/release/tag-a-release.mjs",
  ],
};

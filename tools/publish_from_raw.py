name: Publish from IA RAW to FSPneu

on:
  repository_dispatch:
    types: [publish_recording]
  workflow_dispatch:
    inputs:
      line:
        description: 'Tek satır: "Title | Speaker | Assistant? | DD.MM.YYYY | Hour"'
        required: true
        type: string

permissions:
  contents: write

concurrency:
  group: publish-from-raw
  cancel-in-progress: false

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install requests

      - name: Publish selected raw recording to FSPneu
        env:
          IA_ACCESS_KEY: ${{ secrets.IA_ACCESS_KEY }}
          IA_SECRET_KEY: ${{ secrets.IA_SECRET_KEY }}
          RAW_IA_IDENTIFIER: "FSPraw"
          TARGET_IA_IDENTIFIER: "FSPneu"
          STATE_PATH: ".publish_state.json"
          LINE_FROM_DISPATCH: ${{ github.event.client_payload.line }}
        run: |
          python tools/publish_from_raw.py --line "${LINE_FROM_DISPATCH:-${{ inputs.line }}}"

      - name: Commit publish state (if changed)
        run: |
          set -e
          if git diff --quiet -- .publish_state.json; then
            echo "No publish state changes."
            exit 0
          fi
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .publish_state.json
          git commit -m "chore: update publish state"
          git push

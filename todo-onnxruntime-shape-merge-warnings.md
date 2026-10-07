# TODO: the reCAPTCHA classifier logs three "Error merging shape info" lines on every load

**Owner:** wafer
**Status:** OPEN, low priority (cosmetic). Seen from fetchaller on 2026-10-07,
wafer 0.7.2. No wafer code changed.

## Symptom

Every time the image-grid models load (`wafer/browser/_recaptcha_grid.py`, the
`ort.InferenceSession` built around line 400), onnxruntime writes to stderr,
on macOS and in fetchaller's Linux image alike:

```
[W:onnxruntime:, graph.cc:122 MergeShapeInfo] Error merging shape info for output. 'linear_28' source:{-1,1} target:{-1}. Falling back to lenient merge.
[W:onnxruntime:, graph.cc:122 MergeShapeInfo] Error merging shape info for output. 'linear_43' source:{-1,1} target:{-1}. Falling back to lenient merge.
[W:onnxruntime:, graph.cc:122 MergeShapeInfo] Error merging shape info for output. 'linear_58' source:{-1,1} target:{-1}. Falling back to lenient merge.
```

They are warnings (`W:`) and solving works: the grid solved AliExpress's
reCAPTCHA in that same run. But each line contains "Error", so it reads as a
failure in production logs.

## Likely cause

The `linear_*` outputs (`wafer_cls_s.onnx`, revision `ee0a2667...`) declare a
rank-1 shape `{-1}` while the graph infers `{-1,1}`. That looks like a squeeze
the exporter recorded in the output signature but not in the graph.

## Options

- Re-export the model with output shapes matching the graph, a model revision
  bump (the Dockerfile in fetchaller pins the revision and the files' SHA-256s,
  so it would move with it), or
- set `opts.log_severity_level = 3` on the `SessionOptions` (errors only), if
  you are confident these are the only warnings worth hiding.

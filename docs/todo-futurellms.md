# Future: Visual CAPTCHAs Beyond Google reCAPTCHA

What comes after the local reCAPTCHA solver is stable.

See `llms-local-part1.txt` and `llms-local-part2.txt` for the current
reCAPTCHA 3x3/4x4 solver (EfficientNet classification + D-FINE detection).

## The Problem: Open-Ended Prompts

Google reCAPTCHA uses a fixed set of ~14 categories. We can train a model
once and it works indefinitely. The CAPTCHAs below are fundamentally
different - they use open-ended, rotating prompts that defeat any fixed
model.

## CAPTCHA Types

### 1. hCaptcha grid (image_label_binary)
- 3x3 grid, "click all images containing a [object]"
- Open-ended prompt space (any noun - animals, objects, food, rooms)
- New categories appear every few weeks
- AI need: IMAGE CLASSIFICATION (binary per tile)

### 2. hCaptcha area select
- Single image, "click on the [X]" or "draw box around [X]"
- AI need: OBJECT DETECTION (point or bounding box output)

### 3. hCaptcha multiple choice
- One large image + 2-3 text/image options
- AI need: VISUAL QA / SCENE UNDERSTANDING

### 4. Arkose FunCAPTCHA (deprioritized)
- Interactive mini-games: rotation, dice matching, shadow matching
- 1250+ variants, continuously updated by Arkose
- AI need: SPATIAL REASONING + 3D UNDERSTANDING
- Hardest category. Even GPT-4o only gets 33-49% on many types.

## Why Local Models Can't Reliably Solve These

hcaptcha-challenger (QIN2DIM, 2.2k stars, GPL-3.0) is the most mature
open-source hCaptcha solver. They completely abandoned local ONNX models
and switched entirely to Gemini 2.5 Pro API calls.

Why local models fail:
- hCaptcha rotates categories faster than models can be trained
- Fixed-class models (EfficientNet, ResNet) can't handle arbitrary prompts
- Open-vocabulary models (YOLOE, CLIP) handle simple prompts ("bus") but
  fail on complex ones ("the animal that lives in the habitat shown")
- Small local VLMs (SmolVLM-256M, Moondream 2B) lack the reasoning
  ability for anything beyond basic object recognition
- MLX is required for usable VLM speed on Apple Silicon - no good
  cross-platform CPU story, so local VLMs aren't portable anyway
- Arkose FunCAPTCHA requires 3D spatial reasoning that no small model
  can do

Bottom line: these CAPTCHAs require cloud VLM APIs (user-provided key).
Local-only is not a viable primary strategy. The experts tried and gave up.

## If We Build This: Cloud VLM Backend

Requires user-provided API key. Not free, not offline, but actually works.

    class VisionBackend(Protocol):
        async def classify_image(self, image: bytes, prompt: str) -> bool:
            """Does this image match the prompt? (for grid selection)"""
            ...
        async def detect_objects(self, image: bytes, prompt: str) -> list[BBox]:
            """Find objects matching prompt. (for area_select)"""
            ...
        async def answer_question(self, image: bytes, question: str) -> str:
            """Visual QA. (for multiple choice)"""
            ...

Backends:
- GeminiBackend(api_key) - Gemini 2.5 Flash/Pro
- ClaudeBackend(api_key) - Claude with vision
- OpenAIBackend(api_key) - GPT-4o
- ExternalSolverBackend(api_key, service) - 2captcha/capsolver

Cost: ~$0.01-0.05 per challenge solve. Latency: 1-5s per image.

### Niche (low priority)

5. **AWS WAF CAPTCHA** - Not the JS challenge (wafer solves that), but AWS
   can escalate to visual slide/rotate puzzles. Uncommon.

6. **Tencent Captcha** - Slide and click puzzles on Chinese sites. Similar
   to GeeTest but different protocol. Relevant if targeting Chinese sites
   beyond AliExpress (which uses Baxia).

7. **Yandex SmartCaptcha** - Text recognition challenges. Russian sites only.

8. **Custom/proprietary challenges** - Some large sites (banks, airlines)
   roll their own one-off challenge pages outside any standard provider.

## Techniques Worth Borrowing

### From hcaptcha-challenger (GPL-3.0 - study only, DO NOT copy code)

1. **Coordinate Grid Overlay** - Render labeled X/Y axes onto the challenge
   screenshot before sending to the VLM. Transforms "guess the pixel" into
   "read the scale". Makes VLM coordinate output reliable.

2. **HSW Payload Interception** - Intercept hCaptcha's /getcaptcha/ API
   response. Msgpack-encoded, contains request_type, requester_question,
   tasklist with image URIs.

3. **YAML Skill Routing** - Challenge-specific prompt instructions loaded by
   keyword matching. New variants need only a trigger + template, no code.

4. **Unicode Homoglyph Normalization** - hCaptcha uses Cyrillic/Greek
   look-alikes in prompts. NFKC normalize + known homoglyph map.

5. **Structured Output** - Use the VLM's structured output mode (Gemini
   response_schema, OpenAI function calling, Claude tool_use) for typed JSON.

### From Halligan (MIT)

6. **Retry Math** - At 70% accuracy, 3 retries = 97%. Design for "good
   enough" with retry, not perfection.

## Open Source Projects Reference

| Project | License | Study for |
|---------|---------|-----------|
| [hcaptcha-challenger](https://github.com/QIN2DIM/hcaptcha-challenger) | GPL-3.0 | Architecture, coordinate grid, HSW, skill routing. DO NOT copy code. |
| [Halligan](https://github.com/code-philia/Halligan) | MIT | Metamodel abstraction, coarse-to-fine search |

## Priority

Low. Google reCAPTCHA is the most common visual CAPTCHA wafer encounters.
hCaptcha and Arkose are rare in wafer's target use cases. Only build this
if there's real user demand, and only with cloud VLM backends.

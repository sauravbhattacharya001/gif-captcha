# gif-captcha

A case study exploring whether GIF-based CAPTCHAs can distinguish humans from AI — specifically testing GPT-4's ability to describe unexpected events in animated GIFs.

## Case Study: 10 GIFs Used as CAPTCHA Tests

GPT-4 was given each of the 10 GIFs below with the instruction: *"describe the unexpected event"*

### Results

| # | GIF | Human Response | GPT-4 Response |
|---|-----|---------------|----------------|
| 1 | [Duel plot twist](https://tenor.com/view/unexpected-plot-twist-twist-plot-duel-gif-5053664) | One person shot BANG and the other shot BOOM. | Cannot view animations... |
| 2 | [Rappers](https://i.gifer.com/G9lg.gif) | 3 rappers rapping and then one of them roller skates away. | Cannot view animations... |
| 3 | [Skateboarder](https://funnyordie.tumblr.com/post/102557790934/18-more-shocking-gifs-with-unexpected-twist) | Skateboarder does a trick and then flies up in the air. | Cannot view animations... |
| 4 | [Banana mascot](https://www.pinterest.jp/pin/682225043525224271/) | Banana mascot at sports event dances and annoys security guard, who takes mascot's props and does a better dance. | Cannot view animations... |
| 5 | [Tic Tac Toe dog](https://d1nk8hnup7g8zp.cloudfront.net/articles/6pGl2DodxYIFZtKZuQYmdM/3etkyuexk1gwwbyy.gif) | Shiba Inu dog wins at Tic Tac Toe against a human opponent. | Cannot view animations... |
| 6 | [Parent dog](https://d1nk8hnup7g8zp.cloudfront.net/articles/6pGl2DodxYIFZtKZuQYmdM/5im9cju8puvv32x3.gif) | Person preparing a puppy for cooking gets stopped by the parent dog who volunteers instead. | Cannot view animations... |
| 7 | [Mirror illusion](https://d1nk8hnup7g8zp.cloudfront.net/articles/6pGl2DodxYIFZtKZuQYmdM/t4c2qgro3q3mrdn7.gif) | Person's hand seems to touch its reflection, but it's actually both hands of the same person filming with phone held by mouth. | Cannot view animations... |
| 8 | [Highway drift](https://d1nk8hnup7g8zp.cloudfront.net/articles/6pGl2DodxYIFZtKZuQYmdM/sk4kxd7ggjciux8r.gif) | Car in front does a 180-degree drift and back 180 degrees to continue driving normally. | Cannot view animations... |
| 9 | [Road rage hug](https://d1nk8hnup7g8zp.cloudfront.net/articles/6pGl2DodxYIFZtKZuQYmdM/qewkv1xf930v08l1.gif) | Road rage encounter unexpectedly ends with a friendly hug. | Cannot view animations... |
| 10 | [Birthday cake](https://d1nk8hnup7g8zp.cloudfront.net/articles/6pGl2DodxYIFZtKZuQYmdM/a2bv04cd34x8otnc.gif) | Birthday girl's face is smashed onto the cake, but she emerges clean because she had a paper plate face cover. | Cannot view animations... |

### Key Finding

GPT-4 (at the time of testing) was unable to process animated GIF content, giving the same response for every test: *"I currently cannot view animations, including animated GIFs, so I can't provide real-time descriptions of events within them."*

This demonstrates that GIF-based CAPTCHAs requiring comprehension of animated visual narratives could serve as an effective human-verification mechanism against LLMs that lack video/animation understanding.

### 2025 Update: Multimodal Models Change the Landscape

Since this case study was conducted, multimodal LLMs (GPT-4V, GPT-4o, Claude 3.5, Gemini 1.5 Pro) have gained the ability to process images — including individual GIF frames. While full animation comprehension (understanding temporal sequences across frames) remains more challenging, these models can now:

- Describe static frames extracted from GIFs
- Infer likely motion from visual context clues
- Identify objects, people, and scenes in animated content

This means GIF-based CAPTCHAs that rely solely on visual recognition are **no longer sufficient** as a human-verification mechanism. However, CAPTCHAs requiring understanding of *timing*, *narrative surprise*, and *comedic subversion* in animations may still pose challenges for AI systems that process frames independently rather than as a continuous sequence.

## License

[MIT](LICENSE)

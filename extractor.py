'''
extractor.py
Joshua Brown
March 2, 2026
Extract security requirement information from PDFs using gemma 3 1b (https://huggingface.co/google/gemma-3-1b-it)
'''

import os
from pypdf import PdfReader
from language_model import Language_Model

def verify_input_pdf(path) -> bool:
    path = os.path.realpath(path)
    if not os.path.exists(path):
        print(f"[Error]: No such file or no permission to access: \"{path}\"")
        return False
    if not os.path.isfile(path):
        print(f"[Error]: File \"{path}\" is a directory")
        return False
    if not os.path.splitext(path)[-1].lower() == ".pdf":
        print(f"[Error]: File \"{path}\" is not a PDF")
        return False
    return True

def zero_shot_prompt() -> str:
    return """You are extracting structured data.
Extract Key Data Elements from the section below.
Return YAML in this format:

elements:
  - name: <element name>
    requirements:
      - <requirement text>

Only include elements explicitly mentioned.
Return YAML only."""
    # return "Generate a YAML file, based on Key Data Elements you extract from the data below, mapping elements (labeled 'elementN' where 'N' is the numeric element id incrementing with each element, starting at 1) to their names and a list of requirements involving that element. Note that elements may have multiple requirements."

def few_shot_prompt() -> str:
    return "asdas"

def chain_of_thought_prompt() -> str:
    return "Generate a YAML"

def extract_key_data(document_content):
    gemma = Language_Model(2048, "You are acting as part of a software security analysis tool. In your response, do not include follow-up questions or ask for clarifications; simply respond with the answers to the prompted questions. Should you be asked to generate a file, enclose its contents in a markdown code block with the appropriate file type.")
    zero_shot_out = gemma.raw_prompt(f"{zero_shot_prompt()}\n\nBEGIN DATA:\n{document_content}")

    with open("./PROMPT.md", "w") as out:
        out.write(f"# LLM Name\ngemma-3-1b-it\n# Prompt Type\n{zero_shot_prompt()}\n# Prompt Type\nZero-Shot\n# LLM Output\n{zero_shot_out}")
        print(f"[Info]: Prompt log written to ${os.path.realpath("./PROMPT.md")}")

extracted_text = ""
pdfpath = "./testing/cis-r1.pdf"
if os.path.exists(os.path.splitext(pdfpath)[-2] + ".txt"):
    with open(os.path.splitext(pdfpath)[-2] + ".txt", "r") as cache:
        extracted_text = cache.read()
else:
    pdf = PdfReader(pdfpath)
    for page in pdf.pages:
        extracted_text += page.extract_text()

    with open(os.path.splitext(pdfpath)[-2] + ".txt", 'w') as out:
        out.write(extracted_text)
print(extracted_text)
extract_key_data(extracted_text)

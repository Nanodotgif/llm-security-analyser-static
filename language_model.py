from transformers import pipeline, BitsAndBytesConfig
import torch

class Language_Model():
    def __init__(self, max_tokens=1024, system_prompt=''):
        self.system_prompt = system_prompt
        self.gen_kwargs = {
            # "temperature": 0.2,
            # "top_p": 0.9,
            # "repetition_penalty": 1.1,
            "return_full_text": False,
        }       

        self.bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16
        )
        
        self.pipe = pipeline(
            "text-generation",  
            model="google/gemma-3-1b-it",  
            device_map="auto",
            model_kwargs={"quantization_config": self.bnb_config},
            dtype=torch.float16,
            max_new_tokens=max_tokens
        )

    def raw_prompt(self, input) -> str:
        messages = [
            { "role": "system", "content": [{"type": "text", "text": f"{self.system_prompt}"}]},
            { "role": "user", "content": [{"type": "text", "text": f"{input}"}]}
        ]
        output = self.pipe(messages, **self.gen_kwargs)[0]
        return output["generated_text"]
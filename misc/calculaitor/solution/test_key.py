#!/usr/bin/env python3
import os
from openai import OpenAI

# Configure client to connect to the AI server
ai_base_url = os.getenv('AI_SERVER_URL', 'https://generativelanguage.googleapis.com/v1beta/openai/')
ai_api_keys = os.getenv('AI_SERVER_API_KEY').split(',')
ai_model_to_use = os.getenv('AI_SERVER_MODEL', 'models/gemini-2.0-flash')

system_prompt = """You are a helpful assistant"""


for ai_api_key in ai_api_keys:
    try:
        print('Testing key', ai_api_key)

        client = OpenAI(
            base_url = ai_base_url,
            api_key = ai_api_key
        )

        #models = client.models.list()
        #print(models)

        query = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": 'Hey!'}
            ],
            model=ai_model_to_use
        )

        print(query.choices[0].message.content)
    except Exception as e:
        print('Error', e)



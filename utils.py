import os
import sys

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def input_with_prompt(prompt):
    return input(prompt)

def print_header(text):
    print(f"\n{'=' * 50}")
    print(f"{' ' * 2}{text}")
    print(f"{'=' * 50}")

def wait_for_enter():
    input("Pressione Enter para continuar...")

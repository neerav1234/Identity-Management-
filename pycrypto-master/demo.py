import subprocess

def run_zokrates_command(*args, input_data=None):
    try:
        result = subprocess.run(args, input=input_data, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

compiled_output = run_zokrates_command("zokrates", "compile", "--debug", "--input", "computation.zok")
cw = run_zokrates_command("zokrates", "compute-witness", "-a", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1")
print(cw)


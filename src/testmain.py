import subprocess
import sys
import streamlit.testing.v1 as st_test

def test_main_py():
    print("Testing main.py with Streamlit...")
    result = subprocess.run(
        [sys.executable, "-m", "streamlit", "run", os.path.join(SRC_DIR, "main.py")],
        capture_output=True,
        text=True,
        timeout=10  # Stop after 10 seconds
    )
    print("Streamlit output (truncated):")
    print(result.stdout[:500])

def test_main_buttons():
    # Launch the app in test mode
    runner = st_test.AppTest.from_file("main.py")

    # Simulate clicking each button by label
    button_labels = [
        "Button 1",  # Replace with your actual button labels
        "Button 2",
        "Button 3",
        "Button 4",
        "Button 5",
    ]

    for label in button_labels:
        runner = runner.run()
        runner.button(label).click().run()
        # Optionally, check for expected output or state after each click
        print(f"Tested button: {label}")

if __name__ == "__main__":
    test_main_py()
    test_main_buttons()
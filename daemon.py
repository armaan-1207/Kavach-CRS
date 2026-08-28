import time
import subprocess
import sys
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class KavachActiveDefenseHandler(FileSystemEventHandler):
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.last_run = 0

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith('.py'):
            return
        
        # Debounce (don't run constantly if many files save at once)
        if time.time() - self.last_run < 5:
            return
        self.last_run = time.time()

        print(f"\n[DAEMON] Detected modification in {event.src_path}")
        print(f"[DAEMON] Triggering Kavach-CRS Active Defense Pipeline...\n")
        
        try:
            subprocess.run([sys.executable, "cli.py", "run", self.target_dir])
        except Exception as e:
            print(f"[DAEMON] Failed to run pipeline: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python daemon.py <directory_to_watch>")
        sys.exit(1)
        
    target = Path(sys.argv[1]).resolve()
    if not target.is_dir():
        print(f"Error: {target} is not a directory.")
        sys.exit(1)
        
    event_handler = KavachActiveDefenseHandler(str(target))
    observer = Observer()
    observer.schedule(event_handler, str(target), recursive=True)
    observer.start()
    
    print("================================================================")
    print("   KAVACH-CRS -- Active Endpoint Defense Daemon Started")
    print(f"   Monitoring: {target}")
    print("================================================================")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[DAEMON] Shutting down.")
    observer.join()

if __name__ == "__main__":
    main()

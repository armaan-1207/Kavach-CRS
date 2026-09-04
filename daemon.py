import time
import subprocess
import sys
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class KavachActiveDefenseHandler(FileSystemEventHandler):
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.last_run = 0
        self._lock = threading.Lock()

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith('.py'):
            return
        if not self._lock.acquire(blocking=False):
            return
        try:
            if time.time() - self.last_run < 5:
                return
            print(f"\n[DAEMON] Detected modification in {event.src_path}")
            print("[DAEMON] Triggering Kavach-CRS Active Defense Pipeline...\n")
            cli_path = str(Path(__file__).parent / "cli.py")
            subprocess.run(
                [sys.executable, cli_path, "run", self.target_dir],
                timeout=600,
                stdin=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[DAEMON] Failed to run pipeline: {e}")
        finally:
            self.last_run = time.time()
            self._lock.release()

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
    print("   KAVACH-CRS - Active Endpoint Defense Daemon Started")
    print(f"   Monitoring: {target}")
    print("================================================================")
    try:
        while observer.is_alive():
            time.sleep(1)
        print("[DAEMON] Observer died unexpectedly. Exiting.")
        sys.exit(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[DAEMON] Shutting down.")
    observer.join()

if __name__ == "__main__":
    main()

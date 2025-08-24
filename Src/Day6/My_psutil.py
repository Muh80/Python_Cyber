

# import psutil
# import time

# def get_cpu_usage():
#     return psutil.cpu_percent(interval=1)

# def get_memory_info():
#     mem = psutil.virtual_memory()
#     return mem.percent

# def main():
#     while True:
#         cpu_usage = get_cpu_usage()
#         memory_info = get_memory_info()
#         print(f"CPU Usage: {cpu_usage}%")
#         print(f"Memory Usage: {memory_info}%")
#         time.sleep(1)

# if __name__ == "__main__":
#     main()  



import psutil
import time

THRESHOLD = 3
SECONDS = 10

vals = []

print(f"live montring with limit of {THRESHOLD} every {SECONDS} seconds")

while True:
    # print(f"this is the cpu-time{psutil.cpu_times_percent(interval=1)}")
    # print(f"this is the cpu %{psutil.cpu_percent(interval=1)}")
    vals.append(psutil.cpu_percent(interval=1))

    if len(vals) > SECONDS:
        vals.pop(0)
    if len(vals) == SECONDS:
        avg = sum(vals)/SECONDS
        if avg >= THRESHOLD:
            print(f"[ALERT] CPU {avg:.1f}%  {SECONDS}s")
            vals.clear()



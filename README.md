# webMethods Integration Server Packages/Files Export Tool
A tool written in python to export webMethods Integration Server assets (packages, flow services, adapters, etc..) or specific files to a local directory.


Run the following pyinstaller command to build another .exe file from the modified python code:

```bash
  pyinstaller --onefile --windowed --icon=ISExport.ico ISExport.py
```

Sample Server configuration:

![image](https://github.com/user-attachments/assets/687cb331-3b98-44c2-9bde-9c8a59b1a2b9)



Sample Export:

You can export elements copied directly from the IS like so: 

```bash
Default.gohar.flow:testFlowService
```
![image](https://github.com/user-attachments/assets/44e09600-17dd-4113-9584-dbf782a683a9)



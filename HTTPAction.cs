using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Dalamud.Hooking;
using Dalamud.Plugin;
using System.Text;

using Nancy;
using Nancy.Bootstrapper;
using Nancy.Hosting.Self;
using Nancy.TinyIoc;
using Nancy.Extensions;
using System.Linq;
using System.Windows.Forms;
using System.Diagnostics;

namespace HTTPAction
{
    public class HTTPAction : IDalamudPlugin
    {
        public string Name => "HTTPAction";
        public static DalamudPluginInterface pluginInterface;
        public HTTPActionConfiguration Configuration;

        //private delegate void MacroCallDelegate(IntPtr a, IntPtr b);
        private delegate void MacroCallDelegate(IntPtr a, IntPtr b, IntPtr c);

        private static Hook<MacroCallDelegate> macroCallHook;

        private static IntPtr macroBasePtr = IntPtr.Zero;
        //private static IntPtr macroDataPtr = IntPtr.Zero;
        public static IntPtr macroPtr;

        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
        public static IntPtr hwnd;
        const uint WM_KEYUP = 0x101;
        const uint WM_KEYDOWN = 0x100;

        private NancyHost Host;
        private int Port;
        public bool IsServerStarted { get; set; } = false;
        public void Initialize(DalamudPluginInterface pluginInterface) {
            HTTPAction.pluginInterface = pluginInterface;
            Configuration = pluginInterface.GetPluginConfig() as HTTPActionConfiguration ?? new HTTPActionConfiguration();
            try {
                //var macroCallPtr = pluginInterface.TargetModuleScanner.ScanText("E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8D 4D 20 49 8B D6");
                var macroCallPtr = pluginInterface.TargetModuleScanner.ScanText("40 53 56 57 48 83 EC 70 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 60 48 8B 02 49 8B F0");
                //var macroBasePtr = pluginInterface.TargetModuleScanner.GetStaticAddressFromSig("48 8B 05 ?? ?? ?? ?? 48 8B D9 8B 40 14 85 C0");
                macroBasePtr = Marshal.ReadIntPtr(pluginInterface.TargetModuleScanner.Module.BaseAddress + 0x1BDFEF0);
                macroBasePtr = Marshal.ReadIntPtr(macroBasePtr);
                //PluginLog.Log($"macroBasePtrC={macroBasePtr}");
                macroCallHook = new Hook<MacroCallDelegate>(macroCallPtr, new MacroCallDelegate(MacroCallDetour));
                macroCallHook?.Enable();

                pluginInterface.CommandManager.AddHandler("/macrohttp", new Dalamud.Game.Command.CommandInfo(OnMacroCommandHandler) {
                    HelpMessage = "Send and Execute a Macro By HTTP Requests",
                    ShowInHelp = true
                });
                InitMem();
                hwnd = Process.GetCurrentProcess().MainWindowHandle;
                Port = Configuration.Port;
                //PluginLog.LogError($"HTTP server Started on http://localhost:{Port}!");
                OnStartServer();
            }
            catch (Exception ex) {
                PluginLog.LogError(ex.ToString());
            }
        }

        public void Dispose() {
            pluginInterface.CommandManager.RemoveHandler("/macrohttp");
            FreeMem();
            if(IsServerStarted)
                OnStopServer();
            macroCallHook?.Disable();
            macroCallHook?.Dispose();
        }

        private void MacroCallDetour(IntPtr a, IntPtr b, IntPtr c) {
            macroCallHook?.Original(a, b, c);
            //macroBasePtr = a;
            //macroBasePtrB = c;
            //pluginInterface.Framework.Gui.Chat.PrintError($"a={a}");
            //pluginInterface.Framework.Gui.Chat.PrintError($"c={c}");
            //pluginInterface.Framework.Gui.Chat.PrintError($"macroBasePtrC={macroBasePtrC}");
            //pluginInterface.Framework.Gui.Chat.PrintError($"macroBasePtrD={macroBasePtrD}");
        }

        public static void WriteMacroUnit(IntPtr macroUnitPtr, string payload) {
            var offset_addr = macroUnitPtr;
            var offset_len = macroUnitPtr + 16;
            var offset_flag = macroUnitPtr + 32;
            var offset_payload = macroUnitPtr + 34;
            Marshal.WriteInt64(offset_addr, (long)offset_payload);
            byte[] bytes = Encoding.UTF8.GetBytes(payload);
            Marshal.WriteInt64(offset_len, bytes.Length + 1);
            if (bytes.Length == 0)
                Marshal.WriteInt16(offset_flag, 0x0101);
            else
                Marshal.WriteInt16(offset_flag, 0x0100);
            //byte[] payload_buffer = new byte[70];
            byte[] payload_buffer = new byte[400];
            Buffer.BlockCopy(bytes, 0, payload_buffer, 0, bytes.Length);
            Marshal.Copy(payload_buffer, 0, offset_payload, payload_buffer.Length);
        }

        public static void FreeMem() {
            Marshal.FreeHGlobal(macroPtr);
        }
        public static void InitMem() {
            int blockSize = 500;
            macroPtr = Marshal.AllocHGlobal(blockSize);
            Marshal.Copy(new byte[blockSize], 0, macroPtr, blockSize);
        }
        public static void OnHttpRecivedMacroData(string data) {
            PluginLog.Log($"HTTPAction Received:{data}");
            if (macroBasePtr != IntPtr.Zero && macroPtr != IntPtr.Zero) {
                string[] macroLines = (data).Split('|');
                for (int i = 0; i < macroLines.Length; i++) {
                    WriteMacroUnit(macroPtr, macroLines[i]);
                    macroCallHook.Original(macroBasePtr+ 642424, macroPtr, macroBasePtr);
                }
            }
        }

        public static void OnHttpRecivedKeyData(string data) {
            //pluginInterface.Framework.Gui.Chat.PrintError($"{data}");
            //macroBasePtrC = pluginInterface.TargetModuleScanner.GetStaticAddressFromSig("48 89 0D ?? ?? ?? ?? 48 8B 4D 28 48 89 0D");
            //pluginInterface.Framework.Gui.Chat.PrintError($"{macroBasePtrC}");
            if (int.TryParse(data, out int keycode)) {
                IntPtr res = IntPtr.Zero;
                if (hwnd != IntPtr.Zero) {
                    //pluginInterface.Framework.Gui.Chat.PrintError($"KeyCode:{keycode}");
                    res = SendMessage(hwnd, 0x100, (IntPtr)keycode, (IntPtr)0);
                    res = SendMessage(hwnd, 0x101, (IntPtr)keycode, (IntPtr)0);
                }
            }
            else
            pluginInterface.Framework.Gui.Chat.PrintError($"Error KeyCode:{keycode}\nRecieved Data:{data}");

        }
        public void OnMacroCommandHandler(string command, string args) {
            try {
                if (macroBasePtr != IntPtr.Zero && macroPtr != IntPtr.Zero) {
                    var argSplit = args.Split(' ');

                    switch (argSplit[0]) {
                        case "start": {
                                if (IsServerStarted)
                                    pluginInterface.Framework.Gui.Chat.PrintError($"The HTTP Server is already Started.");
                                else {
                                    OnStartServer();
                                    pluginInterface.Framework.Gui.Chat.PrintError($"The HTTP Server is Started.");
                                }
                                break;
                            }
                        case "stop": {
                                if (IsServerStarted) {
                                    OnStopServer();
                                    pluginInterface.Framework.Gui.Chat.PrintError($"The HTTP Server is Stoped.");
                                }   
                                else
                                    pluginInterface.Framework.Gui.Chat.PrintError($"The HTTP Server is NOT Started.");
                                break;
                            }
                        case "restart": {
                                if (IsServerStarted) {
                                    OnStopServer();
                                }
                                else {
                                    OnStopServer();
                                    OnStartServer();
                                }
                                pluginInterface.Framework.Gui.Chat.PrintError($"The HTTP Server Restarted.");
                                pluginInterface.Framework.Gui.Chat.Print($"The URL is http://localhost:{Port}/macro.");
                                break;
                            }
                        case "port": {
                                int.TryParse(argSplit[1], out Port);
                                Configuration.Port = Port;
                                pluginInterface.SavePluginConfig(Configuration);
                                pluginInterface.Framework.Gui.Chat.PrintError($"The HTTP Port is {Port}.\n Restart HTTP Server to Finish Setting.");
                                break;
                            }
                        default: {
                                pluginInterface.Framework.Gui.Chat.Print($"Send a Post request to execute the command.");
                                pluginInterface.Framework.Gui.Chat.Print($"The URL is http://localhost:{Port}/command.");
                                pluginInterface.Framework.Gui.Chat.Print($"The URL is http://localhost:{Port}/sendkey.");
                                pluginInterface.Framework.Gui.Chat.Print($"Marco is splited by '|'.");
                                pluginInterface.Framework.Gui.Chat.Print($"e.g.");
                                pluginInterface.Framework.Gui.Chat.Print($"/e Hello Dalamud|/e By HTTPAction");
                                pluginInterface.Framework.Gui.Chat.Print($"e.g.");
                                pluginInterface.Framework.Gui.Chat.Print($"Send a Post request to execute the macro.");
                                pluginInterface.Framework.Gui.Chat.Print($"/macrohttp start : Start Http Server");
                                pluginInterface.Framework.Gui.Chat.Print($"/macrohttp start : Stop Http Server");
                                pluginInterface.Framework.Gui.Chat.Print($"/macrohttp start : Restart Http Server");
                                pluginInterface.Framework.Gui.Chat.Print($"/macrohttp port [port] : Change the HTTP Port");
                                break;
                            }
                    }
                }
                else {
                    pluginInterface.Framework.Gui.Chat.PrintError("HTTPAction is not ready.\nExecute a macro to finish setup.");
                }
            }
            catch (Exception ex) {
                PluginLog.LogError(ex.ToString());
            }
        }
        public class MacroBootstrapper : DefaultNancyBootstrapper
        {
            protected override void RequestStartup(TinyIoCContainer container, IPipelines pipelines, NancyContext context) {
                pipelines.AfterRequest.AddItemToEndOfPipeline(ctx => {
                    ctx.Response.WithHeader("Access-Control-Allow-Origin", "*")
                                .WithHeader("Access-Control-Allow-Methods", "POST,GET")
                                .WithHeader("Access-Control-Allow-Headers", "Accept, Origin, Content-type");
                });
            }
        }
        private void OnStartServer() {
            Host = new NancyHost(new MacroBootstrapper(), new Uri($"http://localhost:{Port}"));
            // Start the Nancy Host.
            try {
                Host.Start();
                IsServerStarted = true;
                PluginLog.Log($"HTTP server Started on http://localhost:{Port}!");
            }
            catch (Exception ex) {
                PluginLog.LogError($"{ex}\nCould not start the HTTP server!");
            }
        }

        private void OnStopServer() {
            // Start the Nancy Host.
            try {
                Host.Stop();
                IsServerStarted = false;
                PluginLog.Log($"HTTP server Stoped!");
            }
            catch (Exception ex) {
                PluginLog.LogError($"{ex}\nCould not Stop the HTTP server!");
            }
        }
    }
    public class MacroNancyModule : NancyModule
    {
        public MacroNancyModule() {
            Post["/command"] = p => {
                HTTPAction.OnHttpRecivedMacroData(Request.Body.AsString());
                return HttpStatusCode.Accepted;
            };
            Post["/sendkey"] = p => {
                //HTTPAction.OnHttpRecivedData(Request.Body.AsString());
                HTTPAction.OnHttpRecivedKeyData(Request.Body.AsString());
                return HttpStatusCode.Accepted;
            };
        }
    };
}

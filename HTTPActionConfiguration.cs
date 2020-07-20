using System;
using Dalamud.Configuration;

namespace HTTPAction
{
    [Serializable]
    public class HTTPActionConfiguration : IPluginConfiguration
    {

        public int Port { get; set; }
        int IPluginConfiguration.Version { get; set; }

        public HTTPActionConfiguration() {
            Port = 2019;
        }
    }
}

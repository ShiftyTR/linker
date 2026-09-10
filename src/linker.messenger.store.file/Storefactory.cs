using linker.libs;
using linker.libs.extends;
using linker.tunnel.connection;
using LiteDB;
using System.Net;

namespace linker.messenger.store.file
{

    /// <summary>
    /// 持久化
    /// </summary>
    public sealed class Storefactory
    {
        LiteDatabase database;
        public Storefactory()
        {
            Init();
        }

        private void Init()
        {
            BsonMapper bsonMapper = BsonMapper.Global;
            bsonMapper.RegisterType<IPEndPoint>(serialize: (a) => a.ToString(), deserialize: (a) => IPEndPoint.Parse(a.AsString));
            bsonMapper.RegisterType<IPAddress>(serialize: (a) => a.ToString(), deserialize: (a) => IPAddress.Parse(a.AsString));
            bsonMapper.RegisterType<IPAddress[]>(serialize: (a) => a.ToJson(), deserialize: (a) => a.AsString.DeJson<IPAddress[]>());
            bsonMapper.RegisterType<ITunnelConnection>(serialize: (a) => string.Empty, deserialize: (a) => null);
            bsonMapper.RegisterType<IConnection>(serialize: (a) => string.Empty, deserialize: (a) => null);

            try
            {
                if (FileConfig.ForceInMemory)
                {
                    database = new LiteDatabase(new ConnectionString($"Filename=:memory:;Password={Helper.GlobalString}"), bsonMapper);
                }
                else
                {
                    string db = Path.Join(Helper.CurrentDirectory, "./configs/db.db");
                    if (Directory.Exists(Path.GetDirectoryName(db)) == false)
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(db));
                    }
                    
                    database = new LiteDatabase(new ConnectionString($"Filename={db};Password={Helper.GlobalString}"), bsonMapper);
                    database.CheckpointSize = 1000;
                }
            }
            catch (Exception ex)
            {
                LoggerHelper.Instance.Error(ex);
                // This library is also hosted by mobile/desktop applications. Let the host
                // report a failed VPN startup instead of terminating the entire process.
                throw new InvalidOperationException("Unable to initialize the VPN configuration database.", ex);
            }
        }

        public ILiteCollection<T> GetCollection<T>(string name)
        {
            return database.GetCollection<T>(name);
        }
        public IBsonDataReader Execute(string command, BsonDocument parameters = null)
        {
            return database.Execute(command, parameters);
        }

        public void Dispose()
        {
            database.Checkpoint();
            database.Dispose();
        }
    }

}

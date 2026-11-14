{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          name = "sora-env";
          buildInputs = [
            # goEnv
            # gomod2nix
            pkgs.golangci-lint
            pkgs.go
            pkgs.gotools
            pkgs.go-junit-report
            pkgs.go-task
            pkgs.delve
            pkgs.postgresql
            pkgs.garage
          ];
          env = {
            LANG = "en_US.UTF-8";

            PGHOST = "localhost";
            PGPORT = "5432";
            PGUSER = "postgres";
            PGDATABASE = "postgres";
          };
          shellHook = ''

            echo "setup postgresql"
            export PGDATA="$PWD/.pg"
            export SOCKET_DIR="$PWD/.db/postgres-sockets"
            mkdir -p "$SOCKET_DIR"

            if [ ! -d "$PGDATA" ]; then
              echo "initializing postgresql..."
              ${pkgs.postgresql}/bin/initdb -D "$PGDATA" --auth=trust --username=postgres
              cat <<EOF >> "$PGDATA/postgresql.conf"
              # sora dev shell
              unix_socket_directories = '$SOCKET_DIR'
              log_min_messages = warning
              log_min_error_statement = error
              log_min_duration_statement = 100  # ms
              log_connections = on
              log_disconnections = on
              log_duration = on
              log_timezone = 'UTC'
              log_statement = 'all'
              log_directory = 'pg_log'
              log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
              logging_collector = on
            EOF
            fi

            start_postgres() {
              if ${pkgs.postgresql}/bin/pg_ctl -D "$PGDATA" status >/dev/null; then
                echo "postgresql is already running"
              else
                ${pkgs.postgresql}/bin/pg_ctl -D "$PGDATA" -l "$PGDATA/postgres.log" -w start
              fi
            }
            stop_postgres() {
              ${pkgs.postgresql}/bin/pg_ctl -D "$PGDATA" stop
            }



            echo "setup garage s3 storage"
            export garage_data="$PWD/.garage"
            export garage_conf="$garage_data/garage.toml"

            if [ ! -d "$garage_data" ]; then
              mkdir -p "$garage_data"

              cat <<EOF > "$garage_conf"
              # garage config
              metadata_dir = "$garage_data/meta"
              data_dir = "$garage_data/data"
              db_engine = "lmdb"
              metadata_snapshots_dir = "$garage_data/snapshots"

              replication_factor = 1
              consistency_mode = "consistent"

              rpc_bind_addr = "[::]:3901"
              rpc_public_addr = "127.0.0.1:3901"
              rpc_secret = "$(openssl rand -hex 32)"

              [s3_api]
              s3_region = "garage"
              api_bind_addr = "[::]:3900"
              root_domain = ".s3.garage.localhost"

              [s3_web]
              bind_addr = "[::]:3902"
              root_domain = ".web.garage.localhost"
              index = "index.html"

              [k2v_api]
              api_bind_addr = "[::]:3904"

              [admin]
              api_bind_addr = "[::]:3903"
              admin_token = "$(openssl rand -base64 32)"
              metrics_token = "$(openssl rand -base64 32)"
            EOF
            fi

            cat <<EOF > "./garage_setup.sh"
            #!/bin/sh
            echo "setup garage s3 storage"
            ## export GARAGE_LOG_TO_SYSLOG=1
            garage -c "$garage_conf" server > "$garage_data/server.log" 2>&1 &
            until garage -c "$garage_conf" status > /dev/null 2>&1; do
              kill -0 \$! 2> /dev/null || { echo "garage server exited, see $garage_data/server.log"; exit 1; }
              sleep 1
            done
            node_id=\$(garage -c "$garage_conf" node id -q | cut -d@ -f1)
            garage -c "$garage_conf" layout assign -z dc1 -c 1G \$node_id
            garage -c "$garage_conf" layout apply --version 1
            garage -c "$garage_conf" layout show
            garage -c "$garage_conf" status
            garage -c "$garage_conf" bucket create sora-s3
            garage -c "$garage_conf" bucket list
            garage -c "$garage_conf" key create imap-app-key
            garage -c "$garage_conf" key list
            garage -c "$garage_conf" key info imap-app-key
            garage -c "$garage_conf" bucket allow --read --write --owner sora-s3 --key imap-app-key
            garage -c "$garage_conf" repair --yes -a blocks
            garage -c "$garage_conf" stats -a
            echo "app key with secret"
            garage -c "$garage_conf" key info imap-app-key --show-secret

            EOF
            chmod u+x ./garage_setup.sh

            alias garage="garage -c $garage_conf"
            echo "Setup done"

          '';

        };
      });
}

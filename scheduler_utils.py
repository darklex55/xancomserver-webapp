import requests
from mcstatus import JavaServer
from datetime import datetime

def checkEmptyServersScheduler(db, Server, Game_server, SERVER_IP):
    ips = []
    ports = []
    players = []
    statuses = []
    dirs = []
    i=0
    print('Starting Scheduled Work')
    try:
        res = requests.get('http://' + SERVER_IP + '/getMCServers', timeout=2)
        if res.status_code==200:
            res = res.json()
            all_ports = res.get('answer')[1]

            for port in all_ports:
                server = JavaServer.lookup(SERVER_IP+':'+str(port))
                stat = 1
                player = 0
                dir = ''
                
                try:
                    stats = server.status()
                    player = stats.players.online
                    stat = 0
                    dir = res.get('answer')[2][i]
                except:
                    stat=1

                ips.append(SERVER_IP)
                ports.append(str(port))
                players.append(player)
                statuses.append(stat)
                dirs.append(dir)
                i+=1
    except:
        print('Scheduler - Could not communicate with the server.')

    for i in range(len(ips)):
        server_record = Server.query.filter_by(ip=ips[i]).first()
        if server_record:
            game_server_record = Game_server.query.filter_by(server_id=server_record.id).filter_by(port=ports[i]).first()
            if game_server_record:
                if game_server_record.include_schedule:
                    if game_server_record.status == 'offline':
                        if players[i]>0:
                            game_server_record.status = 'schedule_green'
                            db.session.commit()
                        elif players[i]==0 and statuses[i]==0:
                            game_server_record.status = 'schedule_yellow'
                            db.session.commit()
                        else:
                            game_server_record.status = 'offline'
                            db.session.commit()

                    elif game_server_record.status == 'schedule_green' or (game_server_record.status == 'offline' and players[i]<1):
                        if players[i]<1:
                            game_server_record.status = 'schedule_yellow'
                            db.session.commit()

                    elif game_server_record.status == 'schedule_yellow':
                        if players[i]>0:
                            game_server_record.status = 'schedule_green'
                            db.session.commit()
                        else:
                            game_server_record.status = 'offline'
                            db.session.commit()
                            if statuses[i]==0:
                                try:
                                    requests.get('http://'+SERVER_IP+'/shutoff_mc_server?name='+dirs[i], timeout=1)
                                except:
                                    print('Could not send shutdown command for game server')

                    print('Record Updated: ' + str(ports[i]) + ' - ' + game_server_record.status)
                    
                
            else:
                new_status = 'schedule_yellow'
                if players[i]>0:
                    new_status = 'schedule_green'
                if statuses[i]==1:
                    new_status = 'offline'

                new_record = Game_server(server_id = server_record.id, port=ports[i], updated_at = datetime.now(), include_schedule = True, status=new_status)
                db.session.add(new_record)
                db.session.commit()

                print('New Record: ' + str(ports[i]) + ' - ' + new_status)

import json
import boto3
import botocore
import csv
import whois
from datetime import datetime


def domainChecker(event, context):

    domainfile = "test.csv"
    output = "output.csv"
    error = ["NOT AVAILABLE"]
    today = str(datetime.today().date())

    s3 = boto3.resource("s3")
    s3_client = boto3.client('s3')
    bucket_name = "domaincheck-bucket"
    bucket = s3.Bucket(bucket_name)
    newname = '/tmp/'+domainfile

    try:
        s3_client.download_file(bucket_name, domainfile, newname)
        # The object does exist.
        with open(newname, 'r') as readfile, open('/tmp/'+output, 'w') as outputfile, open('/tmp/'+'temp.csv', 'w') as writefile:
            reader = csv.reader(readfile)
            mlist = list(reader)
            writer = csv.writer(writefile)
            outputwriter = csv.writer(outputfile)
            if len(mlist) > 50:
                for i in range(len(mlist)):
                    row = mlist[i]
                    if i == 0:
                        data = row+['expiration_date']
                        writer.writerow(data)
                        outputwriter.writerow(data)
                    elif 0 < i < 50:
                        try:
                            w = whois.query(row[0], ignore_returncode=1)
                            if w and w.expiration_date != None:
                                newline = [str(w.expiration_date)]
                            else:
                                newline = error
                                outputwriter.writerow(row+newline)
                        except Exception as e:
                            outputwriter.writerow(row+[e])
                    else:
                        writer.writerow(row)
                body = {
                    "message": "domain checked",
                    "input": event
                }
            else:
                for i, row in enumerate(mlist):
                    if i == 0:
                        data = row+['expiration_date']
                        outputwriter.writerow(data)
                        writer.writerow(data)
                    else:
                        try:
                            w = whois.query(row[0], ignore_returncode=1)
                            if w and w.expiration_date != None:
                                newline = [str(w.expiration_date)]
                            else:
                                newline = error
                                outputwriter.writerow(row+newline)
                        except Exception as e:
                            outputwriter.writerow(row+[e])
                body = {
                    "message": "domain checked, need more domains for the next cycle",
                    "input": event
                }

        readfile.close()
        writefile.close()
        outputfile.close()
        bucket.upload_file('/tmp/'+output, 'output'+today+'.csv')
        bucket.upload_file('/tmp/'+'temp.csv', domainfile)

        response = {
            "statusCode": 200,
            "body": json.dumps(body)
        }

    except:
        raise

    return response

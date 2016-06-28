export class Oauth2Storage {
    private cache: any = {};

    constructor(private storage: Storage) {
        // loads all from storage
        for (let i = 0 ; i < this.storage.length; i++) {
            this.cache[this.storage.key(i)] = this.storage.getItem(this.storage.key(i));
        }
    }

    public set(key: string, value: string) {
        this.cache[key] = value;
        this.saveCache(key);
        return this.cache[key];
    }

    public setJson(key: string, value: any) {
        this.cache[key] = JSON.stringify(value);
        this.saveCache(key);
        return this.cache[key];
    }

    public get(key: string) {
        if (this.cache[key]) {
            return this.cache[key];
        } else {
            return this.storage.getItem(key);
        }
    }

    public getJson(key: string) {
        return JSON.parse(this.get(key));
    }

    public remove(key: string) {
        this.storage.removeItem(key);
    }

    private saveCache(key: string) {
        this.storage.setItem(key, this.cache[key]);
    }

}
